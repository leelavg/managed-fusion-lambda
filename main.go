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
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
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
	fieldManager         = "lambda"
	apply        request = "apply"
	create       request = "create"
	remove       request = "remove"
)

type payload struct {
	K8SApiURL    string   `json:"k8s_api_url"`
	AWSSecretARN string   `json:"aws_secret_arn"`
	Data         []string `json:"data"`
}

type rosaCreds struct {
	Username string `json:"username"`
	Password string `json:"paswword"`
}

type proxyFn func(*http.Request) (*url.URL, error)

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
	switch op {
	case apply:
	case create:
	case remove:
	default:
		return hErr(fmt.Errorf("incorrect request set in env"))
	}

	// to which rosa cluster I need to send request
	if _, err := url.Parse(p.K8SApiURL); err != nil {
		return hErr(fmt.Errorf("unable to parse supplied url"))
	}

	// which secret contains creds for authenticated to rosa cluster
	if !arn.IsARN(p.AWSSecretARN) {
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
func setProxyFromEnv(proxy proxyFn) error {
	var rosa_proxy = os.Getenv("ROSA_PROXY")
	if rosa_proxy != "" {
		proxyURL, err := url.Parse(rosa_proxy)
		if err != nil {
			return hErr(err)
		}
		proxy = http.ProxyURL(proxyURL)
	}
	return nil
}

func getROSACreds(ctx context.Context, secretArn string) (*rosaCreds, error) {

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, hErr(err)
	}

	secretSvc := secretsmanager.NewFromConfig(awsCfg)
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretArn),
	}

	result, err := secretSvc.GetSecretValue(ctx, input)
	if err != nil {
		return nil, hErr(err)
	}

	c := &rosaCreds{}
	err = json.Unmarshal([]byte(*result.SecretString), c)
	if err != nil {
		return nil, hErr(err)
	}
	return c, nil
}

func getAccessToken(ctx context.Context, client *http.Client, creds rosaCreds, epURL string) (string, error) {

	wellKnown := fmt.Sprintf("%s/.well-known/oauth-authorization-server", epURL)
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
	if authCodeRes.StatusCode != http.StatusOK {
		return "", hErr(fmt.Errorf("not '200 OK'"))
	}

	urlLocation, err := url.Parse(authCodeRes.Header.Get("Location"))
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

	// one way encoding to get token name in cluster from bearer token
	prefix := "sha256~"
	name := strings.TrimPrefix(token, prefix)
	h := sha256.Sum256([]byte(name))
	tokenName := prefix + base64.RawURLEncoding.EncodeToString(h[0:])
	tokenURL := fmt.Sprintf("%s/apis/oauth.openshift.io/v1/oauthaccesstokens/%s", epURL, tokenName)

	req, err := http.NewRequest(http.MethodDelete, tokenURL, nil)
	if err != nil {
		return hErr(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := client.Do(req)
	if err != nil {
		return hErr(err)
	}
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
	_, err := dri.Create(ctx, obj, metav1.CreateOptions{FieldManager: fieldManager})
	if err != nil {
		return hErr(err)
	}
	return nil
}

func doRemove(ctx context.Context, dri dynamic.ResourceInterface, obj *unstructured.Unstructured) error {
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

	// get rosa login details
	creds, err := getROSACreds(ctx, p.AWSSecretARN)
	if err != nil {
		return "", hErr(err)
	}

	// create a http client for getting access token
	tp := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	if err := setProxyFromEnv(tp.Proxy); err != nil {
		return "", hErr(err)
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
	err = setProxyFromEnv(rc.Proxy)
	if err != nil {
		return "", hErr(err)
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
	for _, d := range p.Data {

		// the returned dynamic client knows how to interact with the supplied resource
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