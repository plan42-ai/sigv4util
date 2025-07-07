package sigv4clientutil

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeCanonicalRequestHash(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	hashedHeaders := map[string]bool{"host": true}

	hash, err := ComputeCanonicalRequestHash(req, hashedHeaders)
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
}

func TestGetHashHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Add("X-EventHorizon-SignedHeaders", "host")

	headers := GetHashHeaders(req)
	assert.Contains(t, headers, "host")
}

func TestCopyReq(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com", bytes.NewBufferString("body content"))
	reqCopy, body, err := CopyReq(req)

	assert.NoError(t, err)
	assert.Equal(t, req.Body, reqCopy.Body)
	assert.Equal(t, "body content", string(body))
}

func TestCanonicalizeRequest(t *testing.T) {
	testCases := []struct {
		requestHTTP              *http.Request
		expectedCanonicalization string
	}{
		{
			requestHTTP:              mustTestRequest(http.MethodGet, "https://example.com"),
			expectedCanonicalization: "GET\n\n\nhost:example.com\nhost\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			requestHTTP:              mustTestRequest(http.MethodGet, "https://example.com?qs=1"),
			expectedCanonicalization: "GET\n\nqs=1\nhost:example.com\nhost\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			requestHTTP:              mustTestRequest(http.MethodGet, "https://example.com", "X-My-Header", " 1 "),
			expectedCanonicalization: "GET\n\n\nhost:example.com\nx-my-header:1\nhost;x-my-header\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			requestHTTP:              mustTestRequest(http.MethodPost, "https://example.com/path"),
			expectedCanonicalization: "POST\n/path\n\nhost:example.com\nhost\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			requestHTTP:              mustTestRequest(http.MethodPost, "https://example.com/path?qs=1&rs=2&ts=+"),
			expectedCanonicalization: "POST\n/path\nqs=1&rs=2&ts=%20\nhost:example.com\nhost\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			requestHTTP:              mustTestRequest(http.MethodGet, "https://example.com/path?qs=1", "X-Abc", "1"),
			expectedCanonicalization: "GET\n/path\nqs=1\nhost:example.com\nx-abc:1\nhost;x-abc\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	for _, tc := range testCases {
		name := strings.ReplaceAll(tc.requestHTTP.URL.String(), "/", "_")
		t.Run(name, func(t *testing.T) {
			canonicalRequest, err := canonicalizeRequest(tc.requestHTTP, 0, HexSha([]byte("")))
			require.NoError(t, err)
			require.Equal(t, tc.expectedCanonicalization, canonicalRequest)
		})
	}
}

func mustTestRequest(method string, u string, headerKV ...string) *http.Request {
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		panic(err)
	}
	for i := 0; i < len(headerKV); i += 2 {
		req.Header.Add(headerKV[i], headerKV[i+1])
	}
	return req
}

func TestHexSha(t *testing.T) {
	data := []byte("test data")
	expectedHash := sha256.Sum256(data)
	expectedHashStr := hex.EncodeToString(expectedHash[:])

	hash := HexSha(data)
	assert.Equal(t, expectedHashStr, hash)
}

func TestAddAuthHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	cfg := &aws.Config{
		Credentials: aws.NewCredentialsCache(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     "AKID",
				SecretAccessKey: "SECRET_KEY",
				SessionToken:    "TOKEN",
			},
		}),
		Region: "us-west-2",
	}

	err := AddAuthHeaders(context.Background(), req, cfg, "us-west-2")
	assert.NoError(t, err)
	assert.NotEmpty(t, req.Header.Get("Authorization"))
}

func TestAddAuthHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	creds := aws.Credentials{
		AccessKeyID:     "AKID",
		SecretAccessKey: "SECRET_KEY",
		SessionToken:    "TOKEN",
	}
	signer := v4.NewSigner()
	requestHash := "testhash"
	region := "us-west-2"

	err := AddAuthHeader(context.Background(), req, creds, signer, requestHash, region)
	assert.NoError(t, err)
	assert.NotEmpty(t, req.Header.Get("Authorization"))
}

func TestCreateStsReq(t *testing.T) {
	requestHash := "testhash"
	region := "us-west-2"

	req, bodyHash, err := CreateStsReq(requestHash, region)
	assert.NoError(t, err)
	assert.NotNil(t, req)
	assert.NotEmpty(t, bodyHash)
}
