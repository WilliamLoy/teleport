/**
 * Copyright 2021 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package auth

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth/mocku2f"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
	"github.com/tstranex/u2f"

	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

type testWithCloudModules struct {
	modules.Modules
}

func (m *testWithCloudModules) Features() modules.Features {
	return modules.Features{
		Cloud: true, // Enable cloud feature which is required for account recovery.
	}
}

// TestGenerateAndUpsertRecoveryCodes tests the following:
//  - generation of recovery codes are of correct format
//  - recovery codes are upserted
//  - recovery codes can be verified and marked used
//  - reusing a used or non-existing token returns error
func TestGenerateAndUpsertRecoveryCodes(t *testing.T) {
	t.Parallel()
	srv := newTestTLSServer(t)
	ctx := context.Background()

	user := "fake@fake.com"
	rc, err := srv.Auth().generateAndUpsertRecoveryCodes(ctx, user)
	require.NoError(t, err)
	require.Len(t, rc, 3)

	// Test codes are not marked used.
	recovery, err := srv.Auth().GetRecoveryCodes(ctx, user)
	require.NoError(t, err)
	for _, token := range recovery.GetCodes() {
		require.False(t, token.IsUsed)
	}

	// Test each codes are of correct format and used.
	for _, code := range rc {
		s := strings.Split(code, "-")

		// 9 b/c 1 for prefix, 8 for words.
		require.Len(t, s, 9)
		require.True(t, strings.HasPrefix(code, "tele-"))

		// Test codes match.
		err := srv.Auth().verifyRecoveryCode(ctx, user, []byte(code))
		require.NoError(t, err)
	}

	// Test used codes are marked used.
	recovery, err = srv.Auth().GetRecoveryCodes(ctx, user)
	require.NoError(t, err)
	for _, token := range recovery.GetCodes() {
		require.True(t, token.IsUsed)
	}

	// Test with a used code returns error.
	err = srv.Auth().verifyRecoveryCode(ctx, user, []byte(rc[0]))
	require.True(t, trace.IsAccessDenied(err))

	// Test with invalid recovery code returns error.
	err = srv.Auth().verifyRecoveryCode(ctx, user, []byte("invalidcode"))
	require.True(t, trace.IsAccessDenied(err))

	// Test with non-existing user returns error.
	err = srv.Auth().verifyRecoveryCode(ctx, "doesnotexist", []byte(rc[0]))
	require.True(t, trace.IsAccessDenied(err))
}

func TestRecoveryCodeEventsEmitted(t *testing.T) {
	t.Parallel()
	srv := newTestTLSServer(t)
	ctx := context.Background()
	mockEmitter := &events.MockEmitter{}
	srv.Auth().emitter = mockEmitter

	user := "fake@fake.com"

	// Test generated recovery codes event.
	tc, err := srv.Auth().generateAndUpsertRecoveryCodes(ctx, user)
	require.NoError(t, err)
	event := mockEmitter.LastEvent()
	require.Equal(t, events.RecoveryCodeGeneratedEvent, event.GetType())
	require.Equal(t, events.RecoveryCodesGenerateCode, event.GetCode())

	// Test used recovery code event.
	err = srv.Auth().verifyRecoveryCode(ctx, user, []byte(tc[0]))
	require.NoError(t, err)
	event = mockEmitter.LastEvent()
	require.Equal(t, events.RecoveryCodeUsedEvent, event.GetType())
	require.Equal(t, events.RecoveryCodeUseSuccessCode, event.GetCode())

	// Re-using the same token emits failed event.
	err = srv.Auth().verifyRecoveryCode(ctx, user, []byte(tc[0]))
	require.Error(t, err)
	event = mockEmitter.LastEvent()
	require.Equal(t, events.RecoveryCodeUsedEvent, event.GetType())
	require.Equal(t, events.RecoveryCodeUseFailureCode, event.GetCode())
}

func TestStartAccountRecovery(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()
	fakeClock := srv.Clock().(clockwork.FakeClock)
	mockEmitter := &events.MockEmitter{}
	srv.Auth().emitter = mockEmitter

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserWithSecondFactorAndRecoveryCodes(srv)
	require.NoError(t, err)

	// Test with no recover type.
	_, err = srv.Auth().StartAccountRecovery(ctx, &proto.StartAccountRecoveryRequest{
		Username:     u.username,
		RecoveryCode: []byte(u.recoveryCodes[0]),
	})
	require.Error(t, err)

	cases := []struct {
		name         string
		recoverType  types.UserTokenUsage
		recoveryCode string
	}{
		{
			name:         "request StartAccountRecovery to recover a MFA",
			recoverType:  types.UserTokenUsage_USER_TOKEN_RECOVER_MFA,
			recoveryCode: u.recoveryCodes[1],
		},
		{
			name:         "request StartAccountRecovery to recover password",
			recoverType:  types.UserTokenUsage_USER_TOKEN_RECOVER_PASSWORD,
			recoveryCode: u.recoveryCodes[2],
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			startToken, err := srv.Auth().StartAccountRecovery(ctx, &proto.StartAccountRecoveryRequest{
				Username:     u.username,
				RecoveryCode: []byte(c.recoveryCode),
				RecoverType:  c.recoverType,
			})
			require.NoError(t, err)
			require.Equal(t, UserTokenTypeRecoveryStart, startToken.GetSubKind())
			require.Equal(t, c.recoverType, startToken.GetUsage())
			require.Equal(t, startToken.GetURL(), fmt.Sprintf("https://<proxyhost>:3080/web/recovery/steps/%s/verify", startToken.GetName()))

			// Test token returned correct byte length.
			bytes, err := hex.DecodeString(startToken.GetName())
			require.NoError(t, err)
			require.Len(t, bytes, RecoveryTokenLenBytes)

			// Test expired token.
			fakeClock.Advance(defaults.RecoveryStartTokenTTL)
			_, err = srv.Auth().GetUserToken(ctx, startToken.GetName())
			require.True(t, trace.IsNotFound(err))

			// Test events emitted.
			event := mockEmitter.LastEvent()
			require.Equal(t, event.GetType(), events.RecoveryTokenCreateEvent)
			require.Equal(t, event.GetCode(), events.RecoveryTokenCreateCode)
			require.Equal(t, event.(*apievents.UserTokenCreate).Name, u.username)
		})
	}
}

func TestStartAccountRecovery_WithLock(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserWithSecondFactorAndRecoveryCodes(srv)
	require.NoError(t, err)

	// Trigger login lock.
	triggerLoginLock(t, srv.Auth(), u.username)

	// Test recovery is still allowed after login lock.
	_, err = srv.Auth().StartAccountRecovery(ctx, &proto.StartAccountRecoveryRequest{
		Username:     u.username,
		RecoveryCode: []byte(u.recoveryCodes[0]),
		RecoverType:  types.UserTokenUsage_USER_TOKEN_RECOVER_MFA,
	})
	require.NoError(t, err)

	// Trigger max failed recovery attempts.
	for i := 1; i <= defaults.MaxAccountRecoveryAttempts; i++ {
		_, err = srv.Auth().StartAccountRecovery(ctx, &proto.StartAccountRecoveryRequest{
			Username: u.username,
		})
		require.True(t, trace.IsAccessDenied(err))

		if i == defaults.MaxAccountRecoveryAttempts {
			require.EqualValues(t, ErrMaxFailedAttemptsFromStartRecovery, err)
		}
	}

	// Test recovery is denied from attempt recovery lock.
	_, err = srv.Auth().StartAccountRecovery(ctx, &proto.StartAccountRecoveryRequest{
		Username:     u.username,
		RecoveryCode: []byte(u.recoveryCodes[1]),
		RecoverType:  types.UserTokenUsage_USER_TOKEN_RECOVER_MFA,
	})
	require.True(t, trace.IsAccessDenied(err))
	require.Equal(t, startRecoveryMaxFailedAttemptsErrMsg, err.Error())

	// Test locks have been placed.
	user, err := srv.Auth().GetUser(u.username, false)
	require.NoError(t, err)
	require.True(t, user.GetStatus().IsLocked)
	require.False(t, user.GetStatus().RecoveryAttemptLockExpires.IsZero())
	require.Equal(t, user.GetStatus().LockExpires, user.GetStatus().RecoveryAttemptLockExpires)
}

func TestStartAccountRecovery_UserErrors(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserWithSecondFactorAndRecoveryCodes(srv)
	require.NoError(t, err)

	cases := []struct {
		desc      string
		expErrMsg string
		req       *proto.StartAccountRecoveryRequest
	}{
		{
			desc:      "username not in valid email format",
			expErrMsg: startRecoveryGenericErrMsg,
			req: &proto.StartAccountRecoveryRequest{
				Username: "malformed-email",
			},
		},
		{
			desc:      "user does not exist",
			expErrMsg: startRecoveryBadAuthnErrMsg,
			req: &proto.StartAccountRecoveryRequest{
				Username: "dne@test.com",
			},
		},
		{
			desc:      "invalid recovery code",
			expErrMsg: startRecoveryBadAuthnErrMsg,
			req: &proto.StartAccountRecoveryRequest{
				Username:     u.username,
				RecoveryCode: []byte("invalid-code"),
			},
		},
		{
			desc:      "missing recover type in request",
			expErrMsg: startRecoveryGenericErrMsg,
			req: &proto.StartAccountRecoveryRequest{
				Username:     u.username,
				RecoveryCode: []byte(u.recoveryCodes[0]),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			_, err = srv.Auth().StartAccountRecovery(ctx, c.req)
			require.True(t, trace.IsAccessDenied(err))
			require.Equal(t, c.expErrMsg, err.Error())
		})
	}
}

func TestApproveAccountRecovery_WithAuthnErrors(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()
	fakeClock := srv.Clock().(clockwork.FakeClock)
	mockEmitter := &events.MockEmitter{}
	srv.Auth().emitter = mockEmitter

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserWithSecondFactorAndRecoveryCodes(srv)
	require.NoError(t, err)

	cases := []struct {
		name            string
		recoverType     types.UserTokenUsage
		getRequest      func() *proto.ApproveAccountRecoveryRequest
		invalidAuthnReq *proto.ApproveAccountRecoveryRequest
	}{
		{
			name:        "authenticate with valid and invalid totp code",
			recoverType: types.UserTokenUsage_USER_TOKEN_RECOVER_PASSWORD,
			invalidAuthnReq: &proto.ApproveAccountRecoveryRequest{
				AuthnCred: &proto.ApproveAccountRecoveryRequest_MFAAuthenticateResponse{MFAAuthenticateResponse: &proto.MFAAuthenticateResponse{
					Response: &proto.MFAAuthenticateResponse_TOTP{TOTP: &proto.TOTPResponse{Code: "invalid-totp-code"}},
				}},
			},
			getRequest: func() *proto.ApproveAccountRecoveryRequest {
				newTOTP, err := totp.GenerateCode(u.otpKey, srv.Clock().Now().Add(30*time.Second))
				require.NoError(t, err)

				return &proto.ApproveAccountRecoveryRequest{
					AuthnCred: &proto.ApproveAccountRecoveryRequest_MFAAuthenticateResponse{MFAAuthenticateResponse: &proto.MFAAuthenticateResponse{
						Response: &proto.MFAAuthenticateResponse_TOTP{TOTP: &proto.TOTPResponse{Code: newTOTP}},
					}},
				}
			},
		},
		{
			name:        "authenticate with valid and invalid u2f response",
			recoverType: types.UserTokenUsage_USER_TOKEN_RECOVER_PASSWORD,
			invalidAuthnReq: &proto.ApproveAccountRecoveryRequest{
				AuthnCred: &proto.ApproveAccountRecoveryRequest_MFAAuthenticateResponse{MFAAuthenticateResponse: &proto.MFAAuthenticateResponse{
					Response: &proto.MFAAuthenticateResponse_U2F{U2F: &proto.U2FResponse{ /* invalid u2f response */ }},
				}},
			},
			getRequest: func() *proto.ApproveAccountRecoveryRequest {
				chal, err := srv.Auth().GetMFAAuthenticateChallenge(u.username, u.password)
				require.NoError(t, err)

				u2fRes, err := u.u2fKey.SignResponse(&u2f.SignRequest{
					Version:   chal.U2FChallenges[0].Version,
					Challenge: chal.U2FChallenges[0].Challenge,
					KeyHandle: chal.U2FChallenges[0].KeyHandle,
					AppID:     chal.U2FChallenges[0].AppID,
				})
				require.NoError(t, err)

				return &proto.ApproveAccountRecoveryRequest{
					AuthnCred: &proto.ApproveAccountRecoveryRequest_MFAAuthenticateResponse{MFAAuthenticateResponse: &proto.MFAAuthenticateResponse{
						Response: &proto.MFAAuthenticateResponse_U2F{U2F: &proto.U2FResponse{
							KeyHandle:  u2fRes.KeyHandle,
							ClientData: u2fRes.ClientData,
							Signature:  u2fRes.SignatureData,
						}},
					}},
				}
			},
		},
		{
			name:        "authenticate with valid and invalid password",
			recoverType: types.UserTokenUsage_USER_TOKEN_RECOVER_MFA,
			invalidAuthnReq: &proto.ApproveAccountRecoveryRequest{
				AuthnCred: &proto.ApproveAccountRecoveryRequest_Password{Password: []byte("invalid-password")},
			},
			getRequest: func() *proto.ApproveAccountRecoveryRequest {
				return &proto.ApproveAccountRecoveryRequest{
					AuthnCred: &proto.ApproveAccountRecoveryRequest_Password{Password: u.password},
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Acquire a start token.
			startToken, err := srv.Auth().createRecoveryToken(ctx, u.username, UserTokenTypeRecoveryStart, c.recoverType)
			require.NoError(t, err)

			// Try a failed attempt, to test it gets cleared later.
			c.invalidAuthnReq.Username = u.username
			c.invalidAuthnReq.RecoveryStartTokenID = startToken.GetName()
			_, err = srv.Auth().ApproveAccountRecovery(ctx, c.invalidAuthnReq)
			require.True(t, trace.IsAccessDenied(err))
			require.Equal(t, approveRecoveryBadAuthnErrMsg, err.Error())

			attempts, err := srv.Auth().GetUserRecoveryAttempts(ctx, u.username)
			require.NoError(t, err)
			require.Len(t, attempts, 1)

			// Get request with authn.
			req := c.getRequest()
			req.Username = u.username
			req.RecoveryStartTokenID = startToken.GetName()

			// Acquire a approve token with the start token.
			approvedToken, err := srv.Auth().ApproveAccountRecovery(ctx, req)
			require.NoError(t, err)
			require.Equal(t, UserTokenTypeRecoveryApproved, approvedToken.GetSubKind())
			require.Equal(t, c.recoverType.String(), approvedToken.GetUsage().String())

			// Test events emitted.
			event := mockEmitter.LastEvent()
			require.Equal(t, event.GetType(), events.RecoveryTokenCreateEvent)
			require.Equal(t, event.GetCode(), events.RecoveryTokenCreateCode)
			require.Equal(t, event.(*apievents.UserTokenCreate).Name, u.username)

			// Test start token got deleted.
			_, err = srv.Auth().GetUserToken(ctx, startToken.GetName())
			require.True(t, trace.IsNotFound(err))

			// Test expired token.
			fakeClock.Advance(defaults.RecoveryApprovedTokenTTL)
			_, err = srv.Auth().GetUserToken(ctx, approvedToken.GetName())
			require.True(t, trace.IsNotFound(err))

			// Test recovery attempts are deleted.
			attempts, err = srv.Auth().GetUserRecoveryAttempts(ctx, u.username)
			require.NoError(t, err)
			require.Len(t, attempts, 0)
		})
	}
}

func TestApproveAccountRecovery_WithLock(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()
	mockEmitter := &events.MockEmitter{}
	srv.Auth().emitter = mockEmitter

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserWithSecondFactorAndRecoveryCodes(srv)
	require.NoError(t, err)

	// Acquire a start token.
	startToken, err := srv.Auth().createRecoveryToken(ctx, u.username, UserTokenTypeRecoveryStart, types.UserTokenUsage_USER_TOKEN_RECOVER_MFA)
	require.NoError(t, err)

	// Trigger login lock.
	triggerLoginLock(t, srv.Auth(), u.username)

	// Test recovery is still allowed after login lock.
	_, err = srv.Auth().ApproveAccountRecovery(ctx, &proto.ApproveAccountRecoveryRequest{
		Username:             u.username,
		RecoveryStartTokenID: startToken.GetName(),
		AuthnCred:            &proto.ApproveAccountRecoveryRequest_Password{Password: u.password},
	})
	require.NoError(t, err)

	// Acquire another start token, as last success would have deleted it.
	startToken, err = srv.Auth().createRecoveryToken(ctx, u.username, UserTokenTypeRecoveryStart, types.UserTokenUsage_USER_TOKEN_RECOVER_MFA)
	require.NoError(t, err)

	// Trigger max failed recovery attempts.
	for i := 1; i <= defaults.MaxAccountRecoveryAttempts; i++ {
		_, err = srv.Auth().ApproveAccountRecovery(ctx, &proto.ApproveAccountRecoveryRequest{
			RecoveryStartTokenID: startToken.GetName(),
			Username:             u.username,
			AuthnCred:            &proto.ApproveAccountRecoveryRequest_Password{Password: []byte("wrong-password")},
		})
		require.True(t, trace.IsAccessDenied(err))

		if i == defaults.MaxAccountRecoveryAttempts {
			require.EqualValues(t, ErrMaxFailedAttemptsFromApproveRecovery, err)
		}
	}

	// Test start token is deleted from max failed attempts.
	_, err = srv.Auth().ApproveAccountRecovery(ctx, &proto.ApproveAccountRecoveryRequest{
		Username:             u.username,
		RecoveryStartTokenID: startToken.GetName(),
		AuthnCred:            &proto.ApproveAccountRecoveryRequest_Password{Password: u.password},
	})
	require.True(t, trace.IsAccessDenied(err))

	// Test only login is locked.
	user, err := srv.Auth().GetUser(u.username, false)
	require.NoError(t, err)
	require.True(t, user.GetStatus().IsLocked)
	require.True(t, user.GetStatus().RecoveryAttemptLockExpires.IsZero())
	require.False(t, user.GetStatus().LockExpires.IsZero())

	// Test recovery attempts got reset.
	attempts, err := srv.Auth().GetUserRecoveryAttempts(ctx, u.username)
	require.NoError(t, err)
	require.Len(t, attempts, 0)
}

func TestChangeAuthnFromAccountRecovery(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := context.Background()
	mockEmitter := &events.MockEmitter{}
	srv.Auth().emitter = mockEmitter

	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testWithCloudModules{})

	u, err := createUserWithSecondFactorAndRecoveryCodes(srv)
	require.NoError(t, err)

	// Test new password with lock that should not affect changing authn.
	triggerLoginLock(t, srv.Auth(), u.username)

	// Acquire an approved token for recovering password.
	approvedToken, err := srv.Auth().createRecoveryToken(ctx, u.username, UserTokenTypeRecoveryApproved, types.UserTokenUsage_USER_TOKEN_RECOVER_PASSWORD)
	require.NoError(t, err)

	err = srv.Auth().ChangeAuthnFromAccountRecovery(ctx, &proto.ChangeAuthnFromAccountRecoveryRequest{
		RecoveryApprovedTokenID: approvedToken.GetName(),
		NewAuthnCred:            &proto.ChangeAuthnFromAccountRecoveryRequest_NewPassword{NewPassword: []byte("llamas-are-cool")},
	})
	require.NoError(t, err)

	// Test locks are removed.
	user, err := srv.Auth().GetUser(u.username, false)
	require.NoError(t, err)
	require.False(t, user.GetStatus().IsLocked)
	require.True(t, user.GetStatus().RecoveryAttemptLockExpires.IsZero())
	require.True(t, user.GetStatus().LockExpires.IsZero())

	// Test login attempts are removed.
	attempts, err := srv.Auth().GetUserLoginAttempts(u.username)
	require.NoError(t, err)
	require.Len(t, attempts, 0)

	// Test adding MFA devices.
	approvedToken, err = srv.Auth().createRecoveryToken(ctx, u.username, UserTokenTypeRecoveryApproved, types.UserTokenUsage_USER_TOKEN_RECOVER_MFA)
	require.NoError(t, err)

	cases := []struct {
		name       string
		getRequest func() *proto.ChangeAuthnFromAccountRecoveryRequest
	}{
		{
			name: "add new TOTP device",
			getRequest: func() *proto.ChangeAuthnFromAccountRecoveryRequest {
				secrets, err := srv.Auth().RotateUserTokenSecrets(context.TODO(), approvedToken.GetName())
				require.NoError(t, err)

				otpCode, err := totp.GenerateCode(secrets.GetOTPKey(), srv.Clock().Now())
				require.NoError(t, err)

				return &proto.ChangeAuthnFromAccountRecoveryRequest{
					NewDeviceName:           "new-otp",
					RecoveryApprovedTokenID: approvedToken.GetName(),
					NewAuthnCred: &proto.ChangeAuthnFromAccountRecoveryRequest_NewMFAResponse{NewMFAResponse: &proto.MFARegisterResponse{
						Response: &proto.MFARegisterResponse_TOTP{TOTP: &proto.TOTPRegisterResponse{Code: otpCode}},
					}},
				}
			},
		},
		{
			name: "add new U2F device",
			getRequest: func() *proto.ChangeAuthnFromAccountRecoveryRequest {
				u2fRegResp, _, err := getMockedU2FAndRegisterRes(srv, approvedToken.GetName())
				require.NoError(t, err)

				return &proto.ChangeAuthnFromAccountRecoveryRequest{
					NewDeviceName:           "new-u2f",
					RecoveryApprovedTokenID: approvedToken.GetName(),
					NewAuthnCred: &proto.ChangeAuthnFromAccountRecoveryRequest_NewMFAResponse{NewMFAResponse: &proto.MFARegisterResponse{
						Response: &proto.MFARegisterResponse_U2F{U2F: u2fRegResp},
					}},
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Get proto request.
			req := c.getRequest()

			// Change authentication.
			err = srv.Auth().ChangeAuthnFromAccountRecovery(ctx, c.getRequest())
			require.NoError(t, err)

			// Test events emitted.
			event := mockEmitter.LastEvent()
			require.Equal(t, event.GetType(), events.MFADeviceAddEvent)
			require.Equal(t, event.GetCode(), events.MFADeviceAddEventCode)
			require.Equal(t, event.(*apievents.MFADeviceAdd).UserMetadata.User, u.username)

			// Test new device has been added.
			mfas, err := srv.Auth().Identity.GetMFADevices(ctx, u.username, false)
			require.NoError(t, err)

			deviceNames := make([]string, 0, len(mfas))
			for _, mfa := range mfas {
				deviceNames = append(deviceNames, mfa.GetName())
			}
			require.Contains(t, deviceNames, req.NewDeviceName)
		})
	}
}

func triggerLoginLock(t *testing.T, srv *Server, username string) {
	for i := 1; i <= defaults.MaxLoginAttempts; i++ {
		_, err := srv.authenticateUser(context.Background(), AuthenticateUserRequest{
			Username: username,
			OTP:      &OTPCreds{},
		})
		require.True(t, trace.IsAccessDenied(err))
	}
}

type userAuthCreds struct {
	recoveryCodes []string
	username      string
	password      []byte
	u2fKey        *mocku2f.Key
	otpKey        string
}

// TODO (codingllama): Unify with test func `configureForMFA`
func createUserWithSecondFactorAndRecoveryCodes(srv *TestTLSServer) (*userAuthCreds, error) {
	ctx := context.Background()
	username := "llama@goteleport.com"
	password := []byte("abc123")

	// Enable second factors.
	ap, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorOn,
		U2F: &types.U2F{
			AppID:  "teleport",
			Facets: []string{"teleport"},
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := srv.Auth().SetAuthPreference(ctx, ap); err != nil {
		return nil, trace.Wrap(err)
	}

	_, _, err = CreateUserAndRole(srv.Auth(), username, []string{username})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resetToken, err := srv.Auth().CreateResetPasswordToken(context.TODO(), CreateUserTokenRequest{
		Name: username,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Insert a password, totp device, and recovery codes.
	u2fRegResp, u2fKey, err := getMockedU2FAndRegisterRes(srv, resetToken.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	res, err := srv.Auth().ChangeUserAuthentication(ctx, &proto.ChangeUserAuthenticationRequest{
		TokenID:     resetToken.GetName(),
		NewPassword: password,
		NewMFARegisterResponse: &proto.MFARegisterResponse{
			Response: &proto.MFARegisterResponse_U2F{U2F: u2fRegResp}},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Insert a totp device manually.
	otpSecret := base32.StdEncoding.EncodeToString([]byte("def456"))
	dev, err := services.NewTOTPDevice("otp", otpSecret, srv.Auth().clock.Now())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err = srv.Auth().UpsertMFADevice(ctx, username, dev); err != nil {
		return nil, trace.Wrap(err)
	}

	return &userAuthCreds{
		username:      username,
		password:      password,
		recoveryCodes: res.GetRecoveryCodes(),
		u2fKey:        u2fKey,
		otpKey:        otpSecret,
	}, nil
}

func getMockedU2FAndRegisterRes(srv *TestTLSServer, tokenID string) (*proto.U2FRegisterResponse, *mocku2f.Key, error) {
	res, err := srv.Auth().CreateSignupU2FRegisterRequest(tokenID)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	u2fKey, err := mocku2f.Create()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	u2fRegResp, err := u2fKey.RegisterResponse(res)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	return &proto.U2FRegisterResponse{
		RegistrationData: u2fRegResp.RegistrationData,
		ClientData:       u2fRegResp.ClientData,
	}, u2fKey, nil
}
