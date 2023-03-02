package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
)

type request string

const (
	apply  request = "apply"
	create request = "create"
	remove request = "remove"
)

const (
	fieldManager         = "lambda"
	rosaProxyEnv         = "ROSA_PROXY"
	wellKnownPath        = ".well-known/oauth-authorization-server"
	oauthAccessTokenPath = "apis/oauth.openshift.io/v1/oauthaccesstokens"
)

type payload struct {
	Request      request  `json:"request"`
	K8SApiURL    string   `json:"k8s_api_url"`
	AWSSecretARN string   `json:"aws_secret_arn"`
	Data         []string `json:"data"`
}

type rosaCreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type SMGetSecretValueInterface interface {
	GetSecretValue(ctx context.Context,
		params *sm.GetSecretValueInput, optFns ...func(*sm.Options)) (*sm.GetSecretValueOutput, error)
}

// TODO: replace with actual error handling
//
// for now this function logs the line where error occured including
// the stack traceable error lines depending on usage
func hErr(err error) error {
	_, _, ln, _ := runtime.Caller(1)
	return fmt.Errorf("[E at %d]: %v;", ln, err)
}

func validatePayload(p payload) error {

	// what am I supposed to do with the resource
	var op request = request(os.Getenv("request"))
	if op == "" {
		op = p.Request
	}
	switch op {
	case apply:
	case create:
	case remove:
	default:
		return hErr(fmt.Errorf("incorrect request set in env"))
	}

	// to which rosa cluster I need to send request
	if _, err := url.ParseRequestURI(p.K8SApiURL); err != nil {
		return hErr(fmt.Errorf("unable to parse supplied url"))
	}

	// which secret contains creds for authenticated to rosa cluster
	if arn, err := arn.Parse(p.AWSSecretARN); err != nil {
		return hErr(fmt.Errorf("incorrect AWS ARN supplied"))
	} else if arn.Service != "secretsmanager" {
		return hErr(fmt.Errorf("incorrect AWS Secret ARN supplied"))
	}

	// on what resource I need to perform the operation
	if len(p.Data) == 0 {
		return hErr(fmt.Errorf("empty data supplied in the invocation"))
	} else {
		for _, d := range p.Data {
			if d == "" {
				return hErr(fmt.Errorf("empty resource data supplied"))
			}
		}
	}

	return nil
}

// useful if we want to reach rosa cluster via proxy
func getProxyFromEnv() (*url.URL, error) {
	var rosaProxy = os.Getenv(rosaProxyEnv)
	var proxyURL *url.URL
	if rosaProxy != "" {
		var err error
		proxyURL, err = url.ParseRequestURI(rosaProxy)
		if err != nil {
			return nil, hErr(err)
		}
	}
	return proxyURL, nil
}

func getSecretValue(ctx context.Context, smClient SMGetSecretValueInterface,
	input *sm.GetSecretValueInput) (*sm.GetSecretValueOutput, error) {
	return smClient.GetSecretValue(ctx, input)
}

func getROSACreds(ctx context.Context, smClient SMGetSecretValueInterface, secretArn string) (*rosaCreds, error) {

	input := &sm.GetSecretValueInput{
		SecretId: aws.String(secretArn),
	}

	result, err := getSecretValue(ctx, smClient, input)
	if err != nil {
		return nil, hErr(err)
	}

	c := &rosaCreds{}
	err = json.Unmarshal([]byte(*result.SecretString), c)
	if err != nil {
		return nil, hErr(err)
	}

	if c.Username == "" || c.Password == "" {
		return nil, hErr(fmt.Errorf("empty creds"))
	}

	return c, nil
}

func getAccessToken(ctx context.Context, client *http.Client, creds rosaCreds, epURL string) (string, error) {

	wellKnown := fmt.Sprintf("%s/%s", epURL, wellKnownPath)
	req, err := http.NewRequest(http.MethodGet, wellKnown, nil)
	if err != nil {
		return "", hErr(err)
	}

	res, err := client.Do(req)
	if err != nil {
		return "", hErr(err)
	}
	if res.StatusCode != http.StatusOK {
		return "", hErr(fmt.Errorf("not '200 OK'"))
	}

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", hErr(err)
	}

	ai := struct {
		AuthEP  string `json:"authorization_endpoint"`
		TokenEP string `json:"token_endpoint"`
	}{}

	err = json.Unmarshal(resBody, &ai)
	if err != nil {
		return "", hErr(err)
	}

	if ai.AuthEP == "" || ai.TokenEP == "" {
		return "", hErr(fmt.Errorf("empty oauth endpoints"))
	}

	cfg := &oauth2.Config{
		ClientID: "openshift-challenging-client",
		Endpoint: oauth2.Endpoint{
			AuthURL:  ai.AuthEP,
			TokenURL: ai.TokenEP,
		},
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	codeClient := &http.Client{
		Transport: client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authCodeUrl := cfg.AuthCodeURL("state", oauth2.AccessTypeOffline)
	authCodeReq, err := http.NewRequest(http.MethodGet, authCodeUrl, nil)
	if err != nil {
		return "", hErr(err)
	}
	authCodeReq.Header.Set("X-CSRF-Token", "x")
	authCodeReq.SetBasicAuth(creds.Username, creds.Password)
	authCodeRes, err := codeClient.Do(authCodeReq)
	if err != nil {
		return "", hErr(err)
	}
	if authCodeRes.StatusCode != http.StatusFound {
		return "", hErr(fmt.Errorf("not '302 StatusFound'"))
	}

	urlLocation, err := url.ParseRequestURI(authCodeRes.Header.Get("Location"))
	if err != nil {
		return "", hErr(err)
	}
	code := urlLocation.Query().Get("code")
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return "", hErr(err)
	}

	if token == nil {
		return "", hErr(fmt.Errorf("empty token received"))
	}

	return token.AccessToken, nil
}

func deleteAccessToken(client *http.Client, token string, epURL string) error {

	// one way hashing to get token name in cluster from bearer token
	prefix := "sha256~"
	name := strings.TrimPrefix(token, prefix)
	h := sha256.Sum256([]byte(name))
	tokenName := prefix + base64.RawURLEncoding.EncodeToString(h[0:])
	tokenURL := fmt.Sprintf("%s/%s/%s", epURL, oauthAccessTokenPath, tokenName)

	req, err := http.NewRequest(http.MethodDelete, tokenURL, nil)
	if err != nil {
		return hErr(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := client.Do(req)
	if err != nil {
		return hErr(err)
	}

	// TODO: decide on retry required or not as the token will anyways expire
	if res.StatusCode != http.StatusOK {
		resBody, _ := ioutil.ReadAll(res.Body)
		fmt.Println(string(resBody))
	}

	return nil
}

func getResourceClient(data string, dc *dynamic.DynamicClient, serializer *kjson.Serializer,
	mapper *restmapper.DeferredDiscoveryRESTMapper) (dynamic.ResourceInterface, *unstructured.Unstructured, error) {

	obj := &unstructured.Unstructured{}
	_, gvk, err := serializer.Decode([]byte(data), nil, obj)
	if err != nil {
		return nil, nil, hErr(err)
	}

	// gvk to gvr mapping
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil, nil, hErr(err)
	}

	// dynamic client for performing ops on the resource inferred from "data"
	var dri dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		dri = dc.Resource(mapping.Resource).Namespace(obj.GetNamespace())
	} else {
		dri = dc.Resource(mapping.Resource)
	}

	return dri, obj, nil
}

func doApply(ctx context.Context, dri dynamic.ResourceInterface, obj *unstructured.Unstructured) error {
	_, err := dri.Apply(ctx, obj.GetName(), obj, metav1.ApplyOptions{FieldManager: fieldManager})
	if err != nil {
		return hErr(err)
	}
	return nil
}

func doCreate(ctx context.Context, dri dynamic.ResourceInterface, obj *unstructured.Unstructured) error {
	// TODO: query resource existing before creating it?
	_, err := dri.Create(ctx, obj, metav1.CreateOptions{FieldManager: fieldManager})
	if err != nil {
		return hErr(err)
	}
	return nil
}

func doRemove(ctx context.Context, dri dynamic.ResourceInterface, obj *unstructured.Unstructured) error {
	// TODO: query resource existing before deleting it?
	err := dri.Delete(ctx, obj.GetName(), metav1.DeleteOptions{})
	if err != nil {
		return hErr(err)
	}
	return nil
}

func HandleRequest(ctx context.Context, p payload) (string, error) {

	// validate before performing any operation
	if err := validatePayload(p); err != nil {
		return "", hErr(err)
	}

	// create AWS Secretsmanager Client
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", hErr(err)
	}
	smClient := sm.NewFromConfig(awsCfg)

	// get rosa login details
	creds, err := getROSACreds(ctx, smClient, p.AWSSecretARN)
	if err != nil {
		return "", hErr(err)
	}

	// create a http client for getting access token
	tp := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	if p, err := getProxyFromEnv(); err != nil {
		return "", hErr(err)
	} else {
		tp.Proxy = http.ProxyURL(p)
	}
	hc := &http.Client{
		Transport: tp,
	}

	// get access token
	token, err := getAccessToken(ctx, hc, *creds, p.K8SApiURL)
	if err != nil {
		return "", hErr(err)
	}

	// invalidate token upon exit
	defer func() {
		err := deleteAccessToken(hc, token, p.K8SApiURL)
		if err != nil {
			fmt.Print(hErr(err))
		}
	}()

	// rest client for k8s communication
	rc := &rest.Config{
		Host:        p.K8SApiURL,
		BearerToken: token,
		UserAgent:   fieldManager,
	}
	if p, err := getProxyFromEnv(); err != nil {
		return "", hErr(err)
	} else {
		rc.Proxy = http.ProxyURL(p)
	}

	// client to lazily discover resources that are available in api server
	dcc, err := discovery.NewDiscoveryClientForConfig(rc)
	if err != nil {
		return "", hErr(err)
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dcc))
	serializer := kjson.NewSerializerWithOptions(
		kjson.DefaultMetaFactory, scheme.Scheme, scheme.Scheme,
		kjson.SerializerOptions{Yaml: false, Pretty: false, Strict: false},
	)

	dc, err := dynamic.NewForConfig(rc)
	if err != nil {
		return "", hErr(err)
	}

	// TODO: Decide a switch in loop vs loop in a switch as we support only
	// one type of request per invocation
	//
	// all ops fail on first error
	var op request = request(os.Getenv("request"))
	if op == "" {
		op = p.Request
	}
	for _, d := range p.Data {

		// the returned dynamic client interface knows how to interact with the supplied resource
		dri, obj, err := getResourceClient(d, dc, serializer, mapper)
		if err != nil {
			return "", hErr(err)
		}

		switch op {
		case apply:
			err := doApply(ctx, dri, obj)
			if err != nil {
				return "", hErr(err)
			}
		case create:
			err := doCreate(ctx, dri, obj)
			if err != nil {
				return "", hErr(err)
			}
		case remove:
			err := doRemove(ctx, dri, obj)
			if err != nil {
				return "", hErr(err)
			}
		}
	}

	return "done", nil
}

func main() {
	lambda.Start(HandleRequest)
}