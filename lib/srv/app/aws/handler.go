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
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"

	appcommon "github.com/gravitational/teleport/lib/srv/app/common"
	"github.com/gravitational/teleport/lib/tlsca"
)

const (
	authorizationHeader = "Authorization"
)

// NewSigningService creates a new instance of SigningService.
func NewSigningService(config SigningServiceConfig) (*SigningService, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)

	}
	return &SigningService{
		SigningServiceConfig: config,
	}, nil
}

// SigningService is an AWS CLI proxy service that signs AWS requests
// based on user identity.
type SigningService struct {
	// SigningServiceConfig is the SigningService configuration.
	SigningServiceConfig
}

// SigningServiceConfig is
type SigningServiceConfig struct {
	// Client is an HTTP client instance used for HTTP calls.
	Client *http.Client
	// Log is the Logger.
	Log logrus.FieldLogger
	// Session is AWS session.
	Session *awssession.Session
	// Clock is used to override time in
	Clock clockwork.Clock

	getSigningCredentials getSigningCredentialsFunc
}

// CheckAndSetDefaults validates the config.
func (s *SigningServiceConfig) CheckAndSetDefaults() error {
	if s.Client == nil {
		s.Client = http.DefaultClient
	}
	if s.Clock == nil {
		s.Clock = clockwork.NewRealClock()
	}
	if s.Log == nil {
		s.Log = logrus.WithField(trace.Component, "aws:signer")
	}
	if s.Session == nil {
		ses, err := awssession.NewSessionWithOptions(awssession.Options{
			SharedConfigState: awssession.SharedConfigEnable,
		})
		if err != nil {
			return trace.Wrap(err)
		}
		s.Session = ses
	}
	if s.getSigningCredentials == nil {
		s.getSigningCredentials = getAWSCredentialsFromSTSAPI
	}
	return nil
}

// Handle handles incoming requests and forward them to the proper AWS API.
// Handling steps:
// 1) Decoded Authorization Header. Authorization Header example:
//
//    Authorization: AWS4-HMAC-SHA256
//    Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,
//    SignedHeaders=host;range;x-amz-date,
//    Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024
//
// 2) Extract credential section from credential Authorization Header.
// 3) Extract aws-region and aws-service from credential section.
// 4) Build AWS API endpoint based on extracted aws-region and aws-service fields.
//    Not that for endpoint resolving the https://github.com/aws/aws-sdk-go/aws/endpoints/endpoints.go
//    package is used and when Amazon release a new API the dependency update is needed.
// 5) Sign HTTP request.
// 6) Forwards the signed HTTP request to the AWS API.
// 7) Forwards API response to the client.
func (s *SigningService) Handle(rw http.ResponseWriter, r *http.Request, identity *tlsca.Identity) {
	resolvedEndpoint, err := resolveEndpoint(r)
	if err != nil {
		s.Log.WithError(err).Error("Failed to resolve endpoint.")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	signedReq, err := s.paperSignedRequest(r, resolvedEndpoint, identity)
	if err != nil {
		s.Log.WithError(err).Error("Failed to create signed request.")
		rw.WriteHeader(http.StatusInternalServerError)
		return

	}
	resp, err := s.Client.Do(signedReq)
	if err != nil {
		s.Log.WithError(err).Error("Failed to send http request.")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	if _, err := io.Copy(rw, resp.Body); err != nil {
		s.Log.WithError(err).Error("Failed to read response body.")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	for k, v := range resp.Header {
		for _, m := range v {
			rw.Header().Add(k, m)
		}
	}
	if resp.StatusCode != http.StatusOK {
		rw.WriteHeader(resp.StatusCode)
	}
}

func resolveEndpoint(r *http.Request) (*endpoints.ResolvedEndpoint, error) {
	awsAuth, err := extractCredFromAuthHeader(r.Header.Get(authorizationHeader))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	resolvedEndpoint, err := endpoints.DefaultResolver().EndpointFor(awsAuth.service, awsAuth.region)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &resolvedEndpoint, nil
}

type awsCredential struct {
	keyID   string
	date    string
	region  string
	service string
}

// extractCredFromAuthHeader extracts the AWS credentials from auth header
// The AWS credential field uses following format:
// <your-access-key-id>/<date>/<aws-region>/<aws-service>/aws4_request
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
func extractCredFromAuthHeader(header string) (*awsCredential, error) {
	if header == "" {
		return nil, trace.BadParameter("failed to find Authorization Header.")
	}
	credential, ok := getAWSCredentialString(header)
	if !ok {
		return nil, trace.BadParameter("failed to find AWS credential section in Authorization Header")
	}
	parts := strings.Split(credential, "/")
	if len(parts) != 5 {
		return nil, trace.BadParameter("failed to split the credential section")
	}
	return &awsCredential{
		keyID:   parts[0],
		date:    parts[1],
		region:  parts[2],
		service: parts[3],
	}, nil

}

func getReadSeeker(reader io.ReadCloser) (io.ReadSeeker, error) {
	switch r := reader.(type) {
	case io.ReadSeeker:
		return r, nil
	default:
		buf, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(buf), nil
	}
}

func (s *SigningService) paperSignedRequest(r *http.Request, resolvedEndpoint *endpoints.ResolvedEndpoint, identity *tlsca.Identity) (*http.Request, error) {
	payload, err := getReadSeeker(r.Body)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	dstURL, err := url.Parse(resolvedEndpoint.URL)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	r.URL.Scheme = dstURL.Scheme
	r.URL.Host = dstURL.Host

	reqCopy, err := http.NewRequest(r.Method, r.URL.String(), payload)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	for k, kv := range r.Header {
		// Remove Teleport app headers.
		if appcommon.IsReservedHeader(k) {
			continue
		}
		for _, v := range kv {
			reqCopy.Header.Add(k, v)
		}
	}
	err = s.signRequestToAWSAPI(reqCopy, payload, resolvedEndpoint.SigningName, resolvedEndpoint.SigningRegion, identity)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return reqCopy, nil
}

// getAWSCredentialString extracts the '<your-access-key-id>/<date>/<aws-region>/<aws-service>/aws4_request' section
// for AWS Authorization Header.
func getAWSCredentialString(header string) (string, bool) {
	const (
		prefix = "Credential="
		suffix = ","
	)
	return getStringInBetweenTwoString(header, prefix, suffix)
}

func getStringInBetweenTwoString(s string, start string, end string) (string, bool) {
	i := strings.Index(s, start)
	if i == -1 {
		return "", false
	}
	offset := i + len(start)
	ns := s[offset:]
	i = strings.Index(ns, end)
	if i == -1 {
		return "", false
	}
	return ns[:i], true
}

type getSigningCredentialsFunc func(c client.ConfigProvider, identity *tlsca.Identity) *credentials.Credentials

func getAWSCredentialsFromSTSAPI(provider client.ConfigProvider, identity *tlsca.Identity) *credentials.Credentials {
	return stscreds.NewCredentials(provider, identity.RouteToApp.AWSRoleARN,
		func(cred *stscreds.AssumeRoleProvider) {
			cred.RoleSessionName = identity.Username
			cred.Expiry.SetExpiration(identity.Expires, 0)
		},
	)
}

func (s *SigningService) signRequestToAWSAPI(req *http.Request, body io.ReadSeeker, service, region string, identity *tlsca.Identity) error {
	signer := v4.NewSigner(s.getSigningCredentials(s.Session, identity))
	_, err := signer.Sign(req, body, service, region, s.Clock.Now())
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}
