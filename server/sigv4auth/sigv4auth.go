package sigv4auth

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/textproto"
	"slices"
	"strings"
	"time"

	"github.com/debugging-sucks/clock"

	sigv4clientutil "github.com/debugging-sucks/sigv4util/client"
)

type Authenticator interface {
	Authenticate(req *http.Request, region string, logger *slog.Logger, clk clock.Clock) (Invoker, error)
}

type Service struct {
	Client HTTPClient
}

func NewAuthService(client HTTPClient) *Service {
	return &Service{Client: client}
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Invoker struct {
	Caller AWSPrincipal
}

type GetCallerIdentityResponse struct {
	GetCallerIdentityResult GetCallerIdentityResult
	ResponseMetadata        ResponseMetadata
}

type GetCallerIdentityResult struct {
	Account string
	Arn     string
	UserID  string
}

type ResponseMetadata struct {
	RequestID string
}

func ParseRequest(requestStr string) (*http.Request, error) {
	ret, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer([]byte(requestStr))))
	if err != nil {
		return nil, err
	}
	ret.RequestURI = ""
	ret.URL.Scheme = "https"
	ret.URL.Host = sigv4clientutil.GetHost(ret)
	ret.Proto = "HTTP/1.1"
	return ret, nil
}

func (a *Service) Authenticate(req *http.Request, currentRegion string, logger *slog.Logger, clk clock.Clock) (Invoker, error) {
	headerName := textproto.CanonicalMIMEHeaderKey("Authorization")
	headerValues := req.Header.Values(headerName)
	if len(headerValues) == 0 {
		logger.ErrorContext(req.Context(), "no 'Authorization' header found", "header", headerName)
		return Invoker{}, NewBadAuthHeaderError(headerName)
	}
	if len(headerValues) > 1 {
		return Invoker{}, NewMultipleAuthHeadersError(headerName)
	}

	parts := strings.SplitN(headerValues[0], " ", 2)
	if len(parts) != 2 || parts[0] != "sts:GetCallerIdentity" {
		logger.ErrorContext(req.Context(), "invalid auth header format", "header", headerName)
		return Invoker{}, NewBadAuthHeaderError(headerName)
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		logger.ErrorContext(req.Context(), "unable to base64 decode auth header", "header", headerName, "error", err)
		return Invoker{}, NewBadAuthHeaderError(headerName)
	}

	embeddedReq, err := ParseRequest(string(decoded))
	if err != nil {
		logger.ErrorContext(req.Context(), "unable to parse auth header", "header", headerName, "error", err)
		return Invoker{}, NewBadAuthHeaderError(headerName)
	}

	err = VerifyStsReq(req, embeddedReq, currentRegion, logger, clk)
	if err != nil {
		logger.ErrorContext(req.Context(), "invalid auth header", "header", headerName, "error", err)
		return Invoker{}, NewBadAuthHeaderError(headerName)
	}

	resp, err := a.Client.Do(embeddedReq)
	if err != nil {
		logger.ErrorContext(req.Context(), "call to 'Sts:GetCallerIdentity' failed", "header", headerName, "error", err)
		return Invoker{}, NewAuthenticationError()
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.ErrorContext(req.Context(), "failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		logger.ErrorContext(req.Context(), "call to 'Sts:GetCallerIdentity' failed", "header", headerName, "status", resp.StatusCode)
		return Invoker{}, NewAuthenticationError()
	}

	contentType := strings.ReplaceAll(resp.Header.Get("Content-Type"), " ", "")
	if contentType != "application/json" && contentType != "application/json;charset=utf-8" && contentType != "" {
		logger.ErrorContext(req.Context(), "unexpected content type", "header", headerName, "content-type", contentType)
		return Invoker{}, NewAuthenticationError()
	}

	var typedResp struct {
		GetCallerIdentityResponse GetCallerIdentityResponse
	}

	err = json.NewDecoder(resp.Body).Decode(&typedResp)
	if err != nil {
		logger.ErrorContext(req.Context(), "unable to parse 'Sts:GetCallerIdentity' response", "header", headerName, "error", err)
		return Invoker{}, NewAuthenticationError()
	}

	if IsAssumeRoleArn(typedResp.GetCallerIdentityResponse.GetCallerIdentityResult.Arn) {
		return Invoker{
			Caller: AWSPrincipal{
				ARN: ToRoleArn(typedResp.GetCallerIdentityResponse.GetCallerIdentityResult.Arn),
			},
		}, nil
	}
	return Invoker{
		Caller: AWSPrincipal{
			ARN: typedResp.GetCallerIdentityResponse.GetCallerIdentityResult.Arn,
		},
	}, nil
}

func ToRoleArn(arn string) string {
	splitColon := strings.SplitN(arn, ":", 6)
	if len(splitColon) != 6 {
		panic("not an assume role arn")
	}
	splitSlash := strings.SplitN(splitColon[5], "/", 3)
	if len(splitSlash) != 3 {
		panic("not an assume role arn")
	}
	return fmt.Sprintf("arn:%v:iam::%v:role/%v", splitColon[1], splitColon[4], splitSlash[1])
}

func IsAssumeRoleArn(arn string) bool {
	split := strings.SplitN(arn, ":", 6)
	if len(split) != 6 {
		return false
	}
	return split[0] == "arn" && split[2] == "sts" && strings.HasPrefix(split[5], "assumed-role/")
}

func VerifyStsReq(origReq *http.Request, stsReq *http.Request, currentRegion string, logger *slog.Logger, clk clock.Clock) error {
	return verify(
		origReq,
		stsReq,
		VerifyAuthenticaionHeader(),
		VerifyPostVerb(),
		VerifyRootPath(),
		VerifyAcceptJSON(),
		VerifyContentType(),
		VerifyAmzonDate(clk),
		VerifyHost(currentRegion),
		VerifyBody(),
		VerifyOrigHash(logger),
	)
}

func VerifyOrigHash(logger *slog.Logger) Verifier {
	return func(origReq, stsReq *http.Request) error {
		expectedHash, err := getHeader(stsReq, "X-Event-Horizon-Request-Hash")
		hashedHeaders := sigv4clientutil.GetHashHeaders(origReq)
		if err != nil {
			return err
		}
		actualHash, err := sigv4clientutil.ComputeCanonicalRequestHash(origReq, hashedHeaders)
		if err != nil {
			return err
		}
		if actualHash != expectedHash {
			logger.ErrorContext(origReq.Context(), "hash mismatch", "expected", expectedHash, "actual", actualHash)
			return NewNotAuthorizedError("hash mismatch")
		}
		return nil
	}
}

func getHeader(req *http.Request, header string) (string, error) {
	values := req.Header.Values(header)
	if len(values) == 0 {
		return "", fmt.Errorf("missing '%v' header", header)
	}
	if len(values) > 1 {
		return "", fmt.Errorf("too many '%v' headers", header)
	}
	return values[0], nil
}

func VerifyBody() Verifier {
	return func(_, stsReq *http.Request) error {
		body, err := getRequestBody(stsReq)
		if err != nil {
			return err
		}
		if body != "Action=GetCallerIdentity&Version=2011-06-15\r\n" {
			return errors.New("not an 'Sts:GetCallerIdentity' request body")
		}
		return nil
	}
}

func getRequestBody(req *http.Request) (string, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	return string(body), nil
}

func VerifyHost(region string) Verifier {
	return func(_, stsReq *http.Request) error {
		if stsReq.Host != fmt.Sprintf("sts.%v.amazonaws.com", region) {
			return errors.New("invalid 'Host' header'")
		}
		return nil
	}
}

func VerifyAmzonDate(clk clock.Clock) Verifier {
	return func(_, stsReq *http.Request) error {
		amzDate, err := getHeader(stsReq, "X-Amz-Date")
		if err != nil {
			return err
		}

		t, err := time.Parse("20060102T150405Z", amzDate)
		if err != nil {
			return fmt.Errorf("unable to parse 'X-Amz-Date' header: %w", err)
		}
		if clk.Now().Sub(t).Abs() > 5*time.Minute {
			return errors.New("'X-Amz-Date' header has expired")
		}
		return nil
	}
}

func VerifyAcceptJSON() Verifier {
	return func(_, stsReq *http.Request) error {
		accept, err := getHeader(stsReq, "Accept")
		if err != nil {
			return err
		}

		if accept != "application/json" {
			return errors.New("'Accept' header is not 'application/json'")
		}
		return nil
	}
}

func VerifyContentType() Verifier {
	return func(_, stsReq *http.Request) error {
		if stsReq.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			return errors.New("'Content-Type' is not 'application/x-www-form-urlencoded'")
		}
		return nil
	}
}

func VerifyRootPath() Verifier {
	return func(_, stsReq *http.Request) error {
		if stsReq.URL.Path != "/" {
			return errors.New("request path is not '/'")
		}
		return nil
	}
}

func VerifyPostVerb() Verifier {
	return func(_, stsReq *http.Request) error {
		if stsReq.Method != "POST" {
			return errors.New("not a 'POST' request")
		}
		return nil
	}
}

func VerifyAuthenticaionHeader() Verifier {
	return func(_, stsReq *http.Request) error {
		authorizationHeader, err := getHeader(stsReq, "Authorization")
		if err != nil {
			return err
		}

		splits := strings.SplitN(authorizationHeader, " ", 2)
		if len(splits) != 2 {
			return errors.New("can't identify signing algorithm")
		}

		if splits[0] != "AWS4-HMAC-SHA256" {
			return errors.New("not using 'AWS4-HMAC-SHA256'")
		}

		pairs := strings.Split(splits[1], ", ")
		if len(pairs) != 3 {
			return errors.New("expected exactly 3 key value pairs in header")
		}
		err = VerifyCredential(pairs[0])
		if err != nil {
			return err
		}
		err = VerifySignedHeaders(pairs[1])
		if err != nil {
			return err
		}
		err = VerifySignature(pairs[2])
		if err != nil {
			return err
		}
		return nil
	}
}

func VerifySignature(s string) error {
	return VerifyKeyName(s, "Signature")
}

func VerifySignedHeaders(s string) error {
	splits := strings.SplitN(s, "=", 2)
	if len(splits) != 2 {
		return errors.New("expected exactly 2 key value pairs in signed headers")
	}
	if splits[0] != "SignedHeaders" {
		return errors.New("expected 'SignedHeaders' key")
	}

	headerList := strings.Split(splits[1], ";")
	if !slices.Contains(headerList, strings.ToLower("X-Event-Horizon-Request-Hash")) {
		return errors.New("'X-Event-Horizon-Request-Hash' is not a signed header")
	}
	return nil
}

func VerifyCredential(s string) error {
	return VerifyKeyName(s, "Credential")
}

func VerifyKeyName(s string, keyName string) error {
	splits := strings.SplitN(s, "=", 2)
	if len(splits) != 2 {
		return errors.New("expected exactly 2 key value pairs in credential")
	}

	if splits[0] != keyName {
		return errors.New("expected 'Credential' key")
	}
	return nil
}

type Verifier func(origReq, stsReq *http.Request) error

func verify(origReq, stsReq *http.Request, verifiers ...Verifier) error {
	for _, v := range verifiers {
		err := v(origReq, stsReq)
		if err != nil {
			return err
		}
	}
	return nil
}
