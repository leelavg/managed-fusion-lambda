package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func TestValidatePayload(t *testing.T) {
	tests := []struct {
		name       string
		p          payload
		shouldFail bool
	}{
		{"empty request", payload{}, true},
		{"incorrect request", payload{Request: "delete"}, true},
		{"no k8surl", payload{Request: "apply"}, true},
		{"no arn", payload{Request: "create", K8SApiURL: "http://api"}, true},
		{"no secret arn", payload{Request: "remove", K8SApiURL: "http://api",
			AWSSecretARN: "arn:aws:s3:::bucket/snap.png"}, true},
		{"no data", payload{Request: "apply", K8SApiURL: "http://api",
			AWSSecretARN: "arn:aws:secretsmanager:::secret:secret"}, true},
		{"empty data", payload{Request: "create", K8SApiURL: "http://api",
			AWSSecretARN: "arn:aws:secretsmanager:::secret:secret", Data: []string{""}}, true},
		{"valid payload", payload{Request: "create", K8SApiURL: "http://api",
			AWSSecretARN: "arn:aws:secretsmanager:::secret:secret", Data: []string{"resource"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePayload(tt.p)
			if tt.shouldFail && err == nil {
				t.Error("should be an invalid payload")
			} else if !tt.shouldFail && err != nil {
				t.Error("should be a valid payload")
			}
		})
	}

}

func TestGetProxyFromEnv(t *testing.T) {
	tests := []struct {
		name       string
		proxy      string
		shouldFail bool
		shouldSet  bool
	}{
		{"no proxy", "", false, false},
		{"incorrect proxy", "0.0.0.0", true, false},
		{"with proxy", "http://0.0.0.0", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			os.Setenv(rosaProxyEnv, tt.proxy)
			defer os.Unsetenv(rosaProxyEnv)

			p, err := getProxyFromEnv()

			if tt.shouldFail && err == nil {
				t.Error("proxy is parsed")
			} else if !tt.shouldFail && err != nil {
				t.Error("proxy is not parsed")
			}

			if tt.shouldSet && fmt.Sprint(p) != tt.proxy {
				t.Error("incorrect proxy set")
			} else if !tt.shouldSet && p != nil {
				t.Error("proxy shouldn't be set")
			}

		})
	}
}

type SMGetSecretValueInterfaceMock struct {
	GetSecretValueFunc func(ctx context.Context,
		params *sm.GetSecretValueInput, optFns ...func(*sm.Options)) (*sm.GetSecretValueOutput, error)
}

func (s SMGetSecretValueInterfaceMock) GetSecretValue(ctx context.Context,
	params *sm.GetSecretValueInput, optFns ...func(*sm.Options)) (*sm.GetSecretValueOutput, error) {
	return s.GetSecretValueFunc(ctx, params, optFns...)
}

var _ SMGetSecretValueInterface = &SMGetSecretValueInterfaceMock{}

func TestGetROSACreds(t *testing.T) {
	secrets := map[string]string{
		"arn1": "{\"username\":\"username\",\"password\":\"password\"}",
		"arn2": "{\"username\":\"\",\"password\":\"password\"}",
		"arn3": "{\"username\":\"\",\"password\":\"\"}",
		"arn4": "{}",
		"arn5": "",
	}

	mockImpl := SMGetSecretValueInterfaceMock{
		GetSecretValueFunc: func(ctx context.Context,
			params *sm.GetSecretValueInput, optFns ...func(*sm.Options)) (*sm.GetSecretValueOutput, error) {

			val, exist := secrets[*params.SecretId]
			if !exist || val == "" {
				return nil, fmt.Errorf("undefined")
			}

			return &sm.GetSecretValueOutput{
				SecretString: aws.String(val),
			}, nil
		},
	}

	tests := []struct {
		name       string
		arn        string
		shouldFail bool
		cred       *rosaCreds
	}{
		{"correct creds", "arn1", false, &rosaCreds{Username: "username", Password: "password"}},
		{"single value empty", "arn2", true, nil},
		{"all values empty", "arn3", true, nil},
		{"both fields missing", "arn4", true, nil},
		{"empty", "arn5", true, nil},
		{"incorrect arn", "arn6", true, nil},
	}

	ctx := context.TODO()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := getROSACreds(ctx, mockImpl, tt.arn)
			if tt.shouldFail && err == nil {
				t.Error("got incomplete creds")
			} else if !tt.shouldFail && !reflect.DeepEqual(tt.cred, cred) {
				t.Error("got incorrect creds")
			}
		})
	}
}

// TODO: implement mock oauth server if required at some point
func TestGetAccessToken(t *testing.T) {

	type r struct {
		headers map[string]string
		body    string
		status  int
	}

	var listenURL string = os.Getenv("LISTEN_URL")
	if listenURL == "" {
		listenURL = "127.0.1.0:12345"
	}
	var httpURL = fmt.Sprintf("http://%s", listenURL)

	var reqRes *string = nil
	responses := map[string]r{
		"req1": {nil, "", 200},
		"req2": {nil,
			`{
			"authorization_endpoint": "` + httpURL + `/oauth/authorize",
			"token_endpoint": "` + httpURL + `/oauth/token"
			}`, 200},
		"req3": {map[string]string{"Location": httpURL + "/oauth?code="},
			`{
			"authorization_endpoint": "` + httpURL + `/oauth/authorize",
			"token_endpoint": "` + httpURL + `/oauth/token"
			}`, 200},
		"req4": {map[string]string{"Location": httpURL + "/oauth?code=123"},
			`{
			"authorization_endpoint": "` + httpURL + `/oauth/authorize",
			"token_endpoint": "` + httpURL + `/oauth/token",
			"access_token": "final_token"
			}`, 200},
		"req5": {nil, "", 500},
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		item := responses[*reqRes]
		if item.headers != nil {
			for k, v := range item.headers {
				res.Header().Set(k, v)
			}
		}
		res.Header().Set("Content-Type", "application/json")

		// this is when we need to provide redirect location
		if req.URL.Query().Get("state") != "" {
			res.WriteHeader(302)
		} else {
			fmt.Fprintf(res, item.body)
		}
	}))
	ts.Listener.Close()
	l, err := net.Listen("tcp", listenURL)
	if err != nil {
		panic(err)
	}
	ts.Listener = l
	ts.Start()
	defer ts.Close()

	tests := []struct {
		name       string
		request    string
		shouldFail bool
	}{
		{"empty response", "req1", true},
		{"no location in header", "req2", true},
		{"no access token", "req3", true},
		{"with access token", "req4", false},
		{"failed request", "req5", true},
	}

	ctx := context.TODO()
	creds := rosaCreds{Username: "username", Password: "password"}
	c := ts.Client()
	apiURL := ts.URL
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqRes = &tt.request
			token, err := getAccessToken(ctx, c, creds, apiURL)
			if tt.shouldFail && err == nil {
				t.Error("incorrect token acquired")
			} else if !tt.shouldFail && token == "" {
				fmt.Println(err)
				t.Error("empty token received")
			}
		})
	}
}

// TODO: reamining tests are of integration based in nature (envtest maybe)
