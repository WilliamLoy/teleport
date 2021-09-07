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

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/srv/alpnproxy"
	"github.com/gravitational/teleport/lib/utils"

	awsarn "github.com/aws/aws-sdk-go/aws/arn"
)

const (
	awsEndpointArg   = "--endpoint-url"
	awsCLIBinaryName = "aws"
)

func onAWS(cf *CLIConf) error {
	// Fake ENV AWS credentials need to be set in order to enforce AWS CLI to
	// sign the request and provide Authorization Header where service-name and region-name are encoded.
	// When endpoint-url AWS CLI flag provides the destination AWS API address is override by endpoint-url value.
	// Teleport AWS Signing APP will resolve aws-service and aws-region to the proper Amazon API URL.
	if err := setFakeAWSEnvCredentials(); err != nil {
		return trace.Wrap(err)
	}

	cli, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}

	cert, err := loadAWSAPPCertificate(cli)
	if err != nil {
		return trace.Wrap(err)
	}

	address, err := utils.ParseAddr(cli.WebProxyAddr)
	if err != nil {
		return trace.Wrap(err)
	}
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return trace.Wrap(err)
	}
	defer listener.Close()

	lp, err := alpnproxy.NewLocalProxy(alpnproxy.LocalProxyConfig{
		Listener:           listener,
		RemoteProxyAddr:    cli.WebProxyAddr,
		Protocol:           alpnproxy.ProtocolAWSCLI,
		InsecureSkipVerify: cf.InsecureSkipVerify,
		ParentContext:      cf.Context,
		SNI:                address.Host(),
		Certs: []tls.Certificate{
			cert,
		},
	})
	if err != nil {
		return trace.Wrap(err)
	}
	defer lp.Close()

	go func() {
		if err := lp.Start(cf.Context); err != nil {
			log.WithError(err).Errorf("Failed to start local proxy.")
		}
	}()

	localProxy := fmt.Sprintf("%s=http://%s", awsEndpointArg, listener.Addr().String())

	args := append([]string{}, cf.AWSCommandArgs...)
	args = append(args, localProxy)
	cmd := exec.Command(awsCLIBinaryName, args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func loadAWSAPPCertificate(cli *client.TeleportClient) (tls.Certificate, error) {
	key, err := cli.LocalAgent().GetKey(cli.SiteName, client.WithAppCerts{})
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}
	cc, ok := key.AppTLSCerts[cli.CurrentAWSCLIApp]
	if !ok {
		return tls.Certificate{}, trace.NotFound("failed to find the %q certificate", cli.CurrentAWSCLIApp)
	}
	cert, err := tls.X509KeyPair(cc, key.Priv)
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}
	return cert, nil
}

func validateANRRole(cf *CLIConf, tc *client.TeleportClient, profile *client.ProfileStatus, arnRole string) error {
	ok := awsarn.IsARN(arnRole)

	validANRs := make(map[string]struct{})
	for _, roleName := range profile.Roles {
		role, err := tc.GetRole(cf.Context, roleName)
		if err != nil {
			return trace.Wrap(err)
		}
		roleARNs := role.GetAWSRoleARNs(types.Allow)
		for _, roleANR := range roleARNs {
			if roleANR == arnRole {
				return nil
			}
			validANRs[roleANR] = struct{}{}
		}
	}
	printMapKeysAs(validANRs, "Available ARNs")
	if !ok {
		// User provided invalid formatted ARN role string, print all available ARN roles for the user and indicate
		// and indicate about invalid ARN format.
		return trace.BadParameter("invalid AWS ARN role format: %q", arnRole)
	}
	return trace.NotFound("user is not allowed to use selected AWS ANR role: %q.", arnRole)
}

func printMapKeysAs(m map[string]struct{}, columnName string) {
	if len(m) == 0 {
		return
	}
	t := asciitable.MakeTable([]string{columnName})
	for k := range m {
		t.AddRow([]string{k})
	}
	fmt.Println(t.AsBuffer().String())

}

// findANRBasedOnRoleName tries to match roleName parameter with allowed user ARNs obtained from the Teleport API based on
// user roles profile. If there is a match the IAM role is created based on accountID and roleName fields.
func findANRBasedOnRoleName(cf *CLIConf, tc *client.TeleportClient, profile *client.ProfileStatus, accountID, roleName string) (string, error) {
	validRolesName := make(map[string]struct{})
	for _, v := range profile.Roles {
		role, err := tc.GetRole(cf.Context, v)
		if err != nil {
			return "", trace.Wrap(err)
		}
		for _, v := range role.GetAWSRoleARNs(types.Allow) {
			arn, err := awsarn.Parse(v)
			if err != nil {
				return "", trace.Wrap(err)
			}

			parts := strings.Split(arn.Resource, "/")
			if len(parts) != 2 {
				continue
			}
			if parts[0] != "role" {
				continue
			}

			if arn.AccountID == accountID {
				validRolesName[parts[1]] = struct{}{}
			}
			if arn.AccountID == accountID && parts[1] == roleName {
				return arn.String(), nil
			}
		}
	}
	if len(validRolesName) != 0 {
		printMapKeysAs(validRolesName, "Available Roles")
	}
	return "", trace.NotFound("Failed to find ANR based on AWS account ID(%q) and RoleName(%q)", accountID, roleName)
}

func setFakeAWSEnvCredentials() error {
	if err := os.Setenv("AWS_ACCESS_KEY_ID", "foo"); err != nil {
		return trace.Wrap(err)
	}
	if err := os.Setenv("AWS_SECRET_ACCESS_KEY", "bar"); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func getARNFromFlags(cf *CLIConf, tc *client.TeleportClient, profile *client.ProfileStatus, app *types.App) (string, error) {
	if cf.AWSRoleARN == "" && cf.AWSRoleName == "" {
		return "", trace.BadParameter("please provide --aws-role-arn or --aws-role-name flag")
	}
	if cf.AWSRoleARN != "" {
		if err := validateANRRole(cf, tc, profile, cf.AWSRoleARN); err != nil {
			return "", trace.Wrap(err)
		}
		return cf.AWSRoleARN, nil
	}
	// Try to construct ANR value based on RoleName and APP AWSAccountID.
	accountID, ok := app.StaticLabels[constants.AWSAccountIDLabel]
	if !ok {
		// APP configuration doesn't contain a accountID value.
		return "", trace.BadParameter("role name is ambiguous, please provide full ARN role name: --aws-role-arn flag")
	}
	var err error
	arn, err := findANRBasedOnRoleName(cf, tc, profile, accountID, cf.AWSRoleName)
	if err != nil {
		return "", trace.Wrap(err)
	}
	return arn, nil
}
