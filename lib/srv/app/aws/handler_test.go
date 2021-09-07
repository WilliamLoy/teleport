/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package appaws

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/tlsca"
)

// TestExtractCredFromAuthHeader test the extractCredFromAuthHeader function logic.
func TestExtractCredFromAuthHeader(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expCred *awsCredential
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:  "valid header",
			input: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024",
			expCred: &awsCredential{
				keyID:   "AKIAIOSFODNN7EXAMPLE",
				date:    "20130524",
				region:  "us-east-1",
				service: "s3",
			},
			wantErr: require.NoError,
		},
		{
			name:    "invalid format",
			input:   "Credential=AKIAIOSFODNN7EXAMPLE/us-east-1/s3/aws4_request",
			wantErr: require.Error,
		},
		{
			name:    "missing credentials section",
			input:   "AWS4-HMAC-SHA256 SignedHeaders=host",
			wantErr: require.Error,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: require.Error,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractCredFromAuthHeader(tc.input)
			tc.wantErr(t, err)
			require.Equal(t, tc.expCred, got)
		})
	}
}

// TestAWSSignerHandler test the AWS SigningService APP handler logic with mocked STS signing credentials.
func TestAWSSignerHandler(t *testing.T) {
	type check func(t *testing.T, resp *s3.ListBucketsOutput, err error)
	checks := func(chs ...check) []check { return chs }

	hasNoErr := func() check {
		return func(t *testing.T, resp *s3.ListBucketsOutput, err error) {
			require.NoError(t, err)
		}
	}

	hasStatusCode := func(wantStatusCode int) check {
		return func(t *testing.T, resp *s3.ListBucketsOutput, err error) {
			apiErr, ok := err.(awserr.RequestFailure)
			if !ok {
				t.Errorf("invalid error type: %T", err)
			}
			require.Equal(t, wantStatusCode, apiErr.StatusCode())
		}
	}

	tests := []struct {
		name                string
		awsClientSession    *session.Session
		wantHost            string
		wantAuthCredService string
		wantAuthCredRegion  string
		wantAuthCredKeyID   string
		checks              []check
	}{
		{
			name: "s3 access",
			awsClientSession: session.Must(session.NewSession(&aws.Config{
				Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: credentials.Value{
					AccessKeyID:     "fakeClientKeyID",
					SecretAccessKey: "fakeClientSecret",
				}}),
				Region: aws.String("us-west-2"),
			})),
			wantHost:            "s3.us-west-2.amazonaws.com",
			wantAuthCredKeyID:   "AKIDl",
			wantAuthCredService: "s3",
			wantAuthCredRegion:  "us-west-2",
			checks: checks(
				hasNoErr(),
			),
		},
		{
			name: "s3 access with different region",
			awsClientSession: session.Must(session.NewSession(&aws.Config{
				Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: credentials.Value{
					AccessKeyID:     "fakeClientKeyID",
					SecretAccessKey: "fakeClientSecret",
				}}),
				Region: aws.String("us-west-1"),
			})),
			wantHost:            "s3.us-west-1.amazonaws.com",
			wantAuthCredKeyID:   "AKIDl",
			wantAuthCredService: "s3",
			wantAuthCredRegion:  "us-west-1",
			checks: checks(
				hasNoErr(),
			),
		},
		{
			name: "s3 access missing credentials",
			awsClientSession: session.Must(session.NewSession(&aws.Config{
				Credentials: credentials.AnonymousCredentials,
				Region:      aws.String("us-west-1"),
			})),
			checks: checks(
				hasStatusCode(http.StatusBadRequest),
			),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(writer http.ResponseWriter, request *http.Request) {
				require.Equal(t, tc.wantHost, request.Host)
				awsCred, err := extractCredFromAuthHeader(request.Header.Get(authorizationHeader))
				require.NoError(t, err)
				require.Equal(t, tc.wantAuthCredRegion, awsCred.region)
				require.Equal(t, tc.wantAuthCredKeyID, awsCred.keyID)
				require.Equal(t, tc.wantAuthCredService, awsCred.service)
			}
			suite := createSuite(t, handler)

			s3Client := s3.New(tc.awsClientSession, &aws.Config{
				Endpoint: &suite.URL,
			})
			resp, err := s3Client.ListBuckets(&s3.ListBucketsInput{})
			for _, check := range tc.checks {
				check(t, resp, err)
			}
		})
	}
}

func staticAWSCredentials(client.ConfigProvider, *tlsca.Identity) *credentials.Credentials {
	return credentials.NewStaticCredentials("AKIDl", "SECRET", "SESSION")
}

func createSuite(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	awsAPIMock := httptest.NewUnstartedServer(handler)
	awsAPIMock.StartTLS()
	t.Cleanup(func() {
		awsAPIMock.Close()
	})

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial(awsAPIMock.Listener.Addr().Network(), awsAPIMock.Listener.Addr().String())
			},
		},
	}

	svc, err := NewSigningService(SigningServiceConfig{
		getSigningCredentials: staticAWSCredentials,
		Client:                client,
		Clock:                 clockwork.NewFakeClock(),
	})
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		svc.Handle(writer, request, &tlsca.Identity{})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(func() {
		server.Close()
	})
	return server
}
