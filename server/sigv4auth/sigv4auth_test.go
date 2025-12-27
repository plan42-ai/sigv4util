package sigv4auth_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/plan42-ai/clock"
	sigv4clientutil "github.com/plan42-ai/sigv4util/client"
	"github.com/plan42-ai/sigv4util/server/sigv4auth"
	"github.com/stretchr/testify/require"
)

type mockHTTPClient struct {
	Response *http.Response
	Err      error
}

func (m *mockHTTPClient) Do(_ *http.Request) (*http.Response, error) {
	return m.Response, m.Err
}

func TestAuthenticate_InvalidAuthHeader(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := createTestRequest(t)

	// Test with invalid Authorization header (missing)
	req.Header.Del("Authorization")
	authService := sigv4auth.NewAuthService(&mockHTTPClient{}) // Inject mock client
	_, err := authService.Authenticate(req, "us-west-2", logger, clock.RealClock{})
	require.Error(t, err)
}

func TestAuthenticate_MultipleAuthHeaders(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := createTestRequest(t)

	// Test with multiple Authorization headers
	req.Header.Add("Authorization", `{"key":"value"}`)
	authService := sigv4auth.NewAuthService(&mockHTTPClient{}) // Inject mock client
	_, err := authService.Authenticate(req, "us-west-2", logger, clock.RealClock{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "multiple 'Authorization' headers")
}

func TestVerifyHost(t *testing.T) {
	origReq := createTestRequest(t)
	stsReq := createTestSTSRequest(t)

	// Modify STS request Host to invalid value
	stsReq.Host = "invalid.amazonaws.com"
	err := sigv4auth.VerifyHost("us-west-2")(origReq, stsReq)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid 'Host' header")
}

func TestVerifyBody_InvalidBody(t *testing.T) {
	origReq := createTestRequest(t)
	stsReq := createTestSTSRequest(t)

	// Modify STS request body
	stsReq.Body = io.NopCloser(bytes.NewBufferString("InvalidBody"))
	err := sigv4auth.VerifyBody()(origReq, stsReq)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an 'Sts:GetCallerIdentity' request body")
}

func TestVerifyOrigHash_Mismatch(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	origReq := createTestRequest(t)
	stsReq := createTestSTSRequest(t)

	// Modify STS request hash
	stsReq.Header.Set("X-Event-Horizon-Request-Hash", "InvalidHash")
	err := sigv4auth.VerifyOrigHash(logger)(origReq, stsReq)
	require.Error(t, err)
	require.Contains(t, err.Error(), "hash mismatch")
}

func TestToRoleArn_ValidArn(t *testing.T) {
	roleArn := sigv4auth.ToRoleArn("arn:aws:sts::123456789012:assumed-role/TestRole/Bob")
	require.Equal(t, "arn:aws:iam::123456789012:role/TestRole", roleArn)
}

func TestToRoleArn_InvalidArn(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for invalid ARN")
		}
	}()

	// This should cause a panic due to invalid ARN structure
	sigv4auth.ToRoleArn("invalid-arn")
}

func TestIsAssumeRoleArn(t *testing.T) {
	require.True(t, sigv4auth.IsAssumeRoleArn("arn:aws:sts::123456789012:assumed-role/TestRole/Bob"))
	require.False(t, sigv4auth.IsAssumeRoleArn("arn:aws:iam::123456789012:user/Bob"))
}

func TestVerifyAmzonDate_Expired(t *testing.T) {
	origReq := createTestRequest(t)
	stsReq := createTestSTSRequest(t)

	// Set an expired X-Amz-Date header
	stsReq.Header.Set("X-Amz-Date", "20200101T120000Z")
	err := sigv4auth.VerifyAmzonDate(clock.RealClock{})(origReq, stsReq)
	require.Error(t, err)
	require.Contains(t, err.Error(), "'X-Amz-Date' header has expired")
}

func TestVerifyAmzonDate_Valid(t *testing.T) {
	origReq := createTestRequest(t)
	stsReq := createTestSTSRequest(t)

	// Set a valid X-Amz-Date header
	stsReq.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	err := sigv4auth.VerifyAmzonDate(clock.RealClock{})(origReq, stsReq)
	require.NoError(t, err)
}

func TestVerifySignedHeaders_Valid(t *testing.T) {
	err := sigv4auth.VerifySignedHeaders("SignedHeaders=host;x-amz-date;x-event-horizon-request-hash")
	require.NoError(t, err)
}

func TestVerifySignedHeaders_MissingHashHeader(t *testing.T) {
	// Missing the X-Event-Horizon-Request-Hash header in SignedHeaders
	err := sigv4auth.VerifySignedHeaders("SignedHeaders=host;x-amz-date")
	require.Error(t, err)
	require.Contains(t, err.Error(), "'X-Event-Horizon-Request-Hash' is not a signed header")
}

func TestVerifyContentType_Invalid(t *testing.T) {
	origReq := createTestRequest(t)
	stsReq := createTestSTSRequest(t)

	// Modify STS request content type
	stsReq.Header.Set("Content-Type", "invalid/content-type")
	err := sigv4auth.VerifyContentType()(origReq, stsReq)
	require.Error(t, err)
	require.Contains(t, err.Error(), "'Content-Type' is not 'application/x-www-form-urlencoded'")
}

func TestVerifyPostVerb_Invalid(t *testing.T) {
	origReq := createTestRequest(t)
	stsReq := httptest.NewRequest(http.MethodGet, "https://sts.us-west-2.amazonaws.com", nil) // Should be POST

	err := sigv4auth.VerifyPostVerb()(origReq, stsReq)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a 'POST' request")
}

func TestVerifyRootPath_Invalid(t *testing.T) {
	origReq := createTestRequest(t)
	stsReq := httptest.NewRequest(
		http.MethodPost,
		"https://sts.us-west-2.amazonaws.com/invalid-path",
		nil,
	) // Should be root "/"

	err := sigv4auth.VerifyRootPath()(origReq, stsReq)
	require.Error(t, err)
	require.Contains(t, err.Error(), "request path is not '/'")
}

func createTestSTSRequest(t *testing.T) *http.Request {
	// Create a sample STS request
	stsReq := httptest.NewRequest(
		http.MethodPost,
		"https://sts.us-west-2.amazonaws.com",
		bytes.NewBufferString("Action=GetCallerIdentity&Version=2011-06-15"),
	)
	stsReq.Header.Set(
		"Authorization",
		"AWS4-HMAC-SHA256 Credential=test, SignedHeaders=host;x-amz-date;x-event-horizon-request-hash, Signature=testsignature",
	)

	// Generate the correct request hash for the test
	req := createTestRequest(t)
	hashedHeaders := sigv4clientutil.GetHashHeaders(req)
	actualHash, err := sigv4clientutil.ComputeCanonicalRequestHash(req, hashedHeaders)
	require.NoError(t, err)

	// Set the correct request hash in the header
	stsReq.Header.Set("X-Event-Horizon-Request-Hash", actualHash)
	stsReq.URL.Path = "/"
	return stsReq
}

func createTestRequest(t *testing.T) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	cfg := &aws.Config{
		Credentials: aws.NewCredentialsCache(
			credentials.StaticCredentialsProvider{
				Value: aws.Credentials{
					AccessKeyID:     "AKID",
					SecretAccessKey: "SECRET",
					SessionToken:    "TOKEN",
				},
			},
		),
		Region: "us-west-2",
	}

	err := sigv4clientutil.AddAuthHeaders(context.Background(), req, cfg, "us-west-2", clock.RealClock{})
	require.NoError(t, err)

	return req
}

func TestAuthenticate_ClientDoError(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := createTestRequest(t)

	// Simulate an error from the mock HTTP client.
	mockClient := &mockHTTPClient{
		Err: fmt.Errorf("client error"),
	}

	// Inject the mock client into the auth service.
	authService := sigv4auth.NewAuthService(mockClient)

	// Call the Authenticate function and expect an error from the mock client.
	_, err := authService.Authenticate(req, "us-west-2", logger, clock.RealClock{})
	require.Error(t, err)
}

func TestAuthenticate_NotAssumeRoleArn(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := createTestRequest(t)

	mockClient := &mockHTTPClient{
		Response: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(
				bytes.NewBufferString(
					`{
				"GetCallerIdentityResponse": {
					"GetCallerIdentityResult": {
						"Arn": "arn:aws:iam::123456789012:user/user-name"
					}
				}
			}`,
				),
			),
		},
	}

	authService := sigv4auth.NewAuthService(mockClient)
	invoker, err := authService.Authenticate(req, "us-west-2", logger, clock.RealClock{})
	require.NoError(t, err)
	require.Equal(t, "arn:aws:iam::123456789012:user/user-name", invoker.Caller.ARN)
}

func TestAuthenticate_IsAssumeRoleArn(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := createTestRequest(t)

	mockClient := &mockHTTPClient{
		Response: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(
				bytes.NewBufferString(
					`{
				"GetCallerIdentityResponse": {
					"GetCallerIdentityResult": {
						"Arn": "arn:aws:sts::123456789012:assumed-role/role-name/role-session-name"
					}
				}
			}`,
				),
			),
		},
	}

	authService := sigv4auth.NewAuthService(mockClient)
	invoker, err := authService.Authenticate(req, "us-west-2", logger, clock.RealClock{})
	require.NoError(t, err)
	require.Equal(t, "arn:aws:iam::123456789012:role/role-name", invoker.Caller.ARN)
}

func TestAuthenticate_JSONDecodeError(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := createTestRequest(t)

	mockClient := &mockHTTPClient{
		Response: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`invalid-json`)),
		},
	}

	authService := sigv4auth.NewAuthService(mockClient)
	_, err := authService.Authenticate(req, "us-west-2", logger, clock.RealClock{})
	require.Error(t, err)
}

func TestAuthenticate_InvalidContentType(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := createTestRequest(t)

	mockClient := &mockHTTPClient{
		Response: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/plain"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
		},
	}

	authService := sigv4auth.NewAuthService(mockClient)
	_, err := authService.Authenticate(req, "us-west-2", logger, clock.RealClock{})
	require.Error(t, err)
}

func TestAuthenticate_ResponseStatusNotOK(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := createTestRequest(t)

	mockClient := &mockHTTPClient{
		Response: &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
		},
	}

	authService := sigv4auth.NewAuthService(mockClient)
	_, err := authService.Authenticate(req, "us-west-2", logger, clock.RealClock{})
	require.Error(t, err)
}

func TestAuthenticate_VerifyStsReqError(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := createTestRequest(t)
	req.Header.Set("Authorization", "sts:GetCallerIdentity aW52YWxpZA==")

	authService := sigv4auth.NewAuthService(&mockHTTPClient{})
	_, err := authService.Authenticate(req, "us-west-2", logger, clock.RealClock{})
	require.Error(t, err)
}

func TestAuthenticate_ParseRequestError(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := createTestRequest(t)
	req.Header.Set("Authorization", "sts:GetCallerIdentity YWJj")

	authService := sigv4auth.NewAuthService(&mockHTTPClient{})
	_, err := authService.Authenticate(req, "us-west-2", logger, clock.RealClock{})
	require.Error(t, err)
}

func TestAuthenticate_BadAuthHeader(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := createTestRequest(t)
	req.Header.Set("Authorization", "invalid-json")

	authService := sigv4auth.NewAuthService(&mockHTTPClient{})
	_, err := authService.Authenticate(req, "us-west-2", logger, clock.RealClock{})
	require.Error(t, err)
}

func TestAuthenticate_NoAuthHeader(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	req := createTestRequest(t)
	req.Header.Del("Authorization")

	authService := sigv4auth.NewAuthService(&mockHTTPClient{})
	_, err := authService.Authenticate(req, "us-west-2", logger, clock.RealClock{})
	require.Error(t, err)
}
