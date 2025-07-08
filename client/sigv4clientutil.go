package sigv4clientutil

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func ComputeCanonicalRequestHash(req *http.Request, hashedHeaders map[string]bool) (string, error) {
	reqCopy, body, err := CopyReq(req)
	if err != nil {
		return "", err
	}

	for k := range reqCopy.Header {
		if !hashedHeaders[textproto.CanonicalMIMEHeaderKey(k)] {
			reqCopy.Header.Del(k)
		}
	}
	cr, err := canonicalizeRequest(reqCopy, len(body), HexSha(body))
	if err != nil {
		return "", err
	}
	return HexSha([]byte(cr)), nil
}

func GetHashHeaders(req *http.Request) map[string]bool {
	headerList := req.Header.Get("X-EventHorizon-SignedHeaders")
	if headerList != "" {
		return stringToSet(headerList)
	}

	hashedHeaders := []string{}
	for k := range req.Header {
		headerName := textproto.CanonicalMIMEHeaderKey(k)
		if strings.HasPrefix(headerName, "Authorization") {
			continue
		}
		hashedHeaders = append(hashedHeaders, headerName)
	}
	hashedHeaders = append(hashedHeaders, textproto.CanonicalMIMEHeaderKey("X-EventHorizon-SignedHeaders"))
	slices.Sort(hashedHeaders)
	req.Header.Add("X-EventHorizon-SignedHeaders", strings.Join(hashedHeaders, ";"))
	return arrayToSet(hashedHeaders)
}

func arrayToSet(arr []string) map[string]bool {
	ret := make(map[string]bool)
	for _, header := range arr {
		ret[header] = true
	}
	return ret
}

func stringToSet(list string) map[string]bool {
	ret := make(map[string]bool)
	for _, header := range strings.Split(list, ";") {
		ret[header] = true
	}
	return ret
}

func CopyReq(req *http.Request) (*http.Request, []byte, error) {
	reqCopy := req.Clone(req.Context())
	var body []byte
	var err error

	if req.Body != nil {
		// req.Clone doesn't copy the body. We need to be able to read it twice, so read the full thing in, then
		// modify both reqs to use a new body with the same content.
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read request body: %w", err)
		}
		_ = req.Body.Close()
	}

	req.Body = io.NopCloser(bytes.NewBuffer(body))
	reqCopy.Body = io.NopCloser(bytes.NewBuffer(body))

	return reqCopy, body, nil
}

func canonicalizeRequest(req *http.Request, length int, bodyHash string) (string, error) {
	buf := bytes.NewBuffer(nil)
	_, err := fmt.Fprintln(buf, strings.ToUpper(req.Method))
	if err != nil {
		return "", err
	}

	_, err = fmt.Fprintln(buf, uriEncode(req.URL))
	if err != nil {
		return "", err
	}

	query := req.URL.Query()
	// Sort Each Query Key's Values
	for key := range query {
		sort.Strings(query[key])
	}
	_, err = fmt.Fprintln(buf, strings.ReplaceAll(query.Encode(), "+", "%20"))
	if err != nil {
		return "", err
	}

	_, err = fmt.Fprintln(buf, canonicalizeHeaders(req, length))
	if err != nil {
		return "", err
	}

	_, err = fmt.Fprint(buf, bodyHash)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

var ignoredHeaders = map[string]bool{
	"Authorization":   true,
	"User-Agent":      true,
	"X-Amzn-Trace-Id": true,
	"Expect":          true,
}

// NOTE: This is taken from the AWS SDK internals, with a few modifications.
func canonicalizeHeaders(req *http.Request, length int) string {
	host := GetHost(req)
	signed := make(http.Header)

	//nolint:prealloc
	var headers []string

	const hostHeader = "host"
	headers = append(headers, hostHeader)
	signed[hostHeader] = append(signed[hostHeader], host)

	const contentLengthHeader = "content-length"
	if length > 0 {
		headers = append(headers, contentLengthHeader)
		signed[contentLengthHeader] = append(signed[contentLengthHeader], fmt.Sprintf("%v", length))
	}

	for k, v := range req.Header {
		if ignoredHeaders[k] {
			continue
		}
		if strings.EqualFold(k, contentLengthHeader) {
			// prevent signing already handled content-length header.
			continue
		}

		lowerCaseKey := strings.ToLower(k)
		if _, ok := signed[lowerCaseKey]; ok {
			// include additional values
			signed[lowerCaseKey] = append(signed[lowerCaseKey], v...)
			continue
		}

		headers = append(headers, lowerCaseKey)
		signed[lowerCaseKey] = v
	}
	sort.Strings(headers)

	signedHeaders := strings.Join(headers, ";")

	var ret strings.Builder
	n := len(headers)
	const colon = ':'
	for i := 0; i < n; i++ {
		if headers[i] == hostHeader {
			ret.WriteString(hostHeader)
			ret.WriteRune(colon)
			ret.WriteString(stripExcessSpaces(host))
		} else {
			ret.WriteString(headers[i])
			ret.WriteRune(colon)
			// Trim out leading, trailing, and dedup inner spaces from signed header values.
			values := signed[headers[i]]
			for j, v := range values {
				cleanedValue := strings.TrimSpace(stripExcessSpaces(v))
				ret.WriteString(cleanedValue)
				if j < len(values)-1 {
					ret.WriteRune(',')
				}
			}
		}
		ret.WriteRune('\n')
	}
	ret.WriteString(signedHeaders)
	return ret.String()
}

// NOTE: This is taken from the AWS SDK, with a few minor changes.
func stripExcessSpaces(str string) string {
	const doubleSpace = "  "
	var j, k, l, m, spaces int
	// Trim trailing spaces
	//revive:disable:empty-block
	for j = len(str) - 1; j >= 0 && str[j] == ' '; j-- {
	}

	// Trim leading spaces
	for k = 0; k < j && str[k] == ' '; k++ {
	}
	//revive:enable:empty-block
	str = str[k : j+1]

	// Strip multiple spaces.
	j = strings.Index(str, doubleSpace)
	if j < 0 {
		return str
	}

	buf := []byte(str)
	for k, m, l = j, j, len(buf); k < l; k++ {
		if buf[k] == ' ' {
			if spaces == 0 {
				// First space.
				buf[m] = buf[k]
				m++
			}
			spaces++
		} else {
			// End of multiple spaces.
			spaces = 0
			buf[m] = buf[k]
			m++
		}
	}

	return string(buf[:m])
}

func GetHost(req *http.Request) string {
	host := req.URL.Host
	if len(req.Host) > 0 {
		host = req.Host
	}
	return host
}

func uriEncode(u *url.URL) any {
	uCopy := *u
	uCopy.RawQuery = ""
	uCopy.Opaque = ""
	return uCopy.EscapedPath()
}

func HexSha(data []byte) string {
	res := sha256.Sum256(data)
	return hex.EncodeToString(res[:])
}

func AddAuthHeaders(ctx context.Context, req *http.Request, cfg *aws.Config, region string) error {
	hashedHeaders := GetHashHeaders(req)

	requestHash, err := ComputeCanonicalRequestHash(req, hashedHeaders)
	if err != nil {
		panic(err)
	}

	signer := v4.NewSigner()
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return err
	}

	err = AddAuthHeader(ctx, req, creds, signer, requestHash, region)
	if err != nil {
		return err
	}

	return nil
}

func AddAuthHeader(ctx context.Context, req *http.Request, creds aws.Credentials, signer *v4.Signer, requestHash string, region string) error {
	stsReq, stsBodyHash, err := CreateStsReq(requestHash, region)
	if err != nil {
		return err
	}
	now := time.Now()

	err = signer.SignHTTP(ctx, creds, stsReq, stsBodyHash, "sts", region, now)
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(nil)
	err = stsReq.Write(buf)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	req.Header.Add("Authorization", "sts:GetCallerIdentity "+encoded)
	return nil
}

func CreateStsReq(requestHash string, region string) (*http.Request, string, error) {
	u, err := url.Parse(fmt.Sprintf("https://sts.%v.amazonaws.com", url.PathEscape(region)))
	if err != nil {
		return nil, "", err
	}

	header := make(http.Header)
	header.Add("Content-Type", "application/x-www-form-urlencoded")
	header.Add("X-Amz-Date", time.Now().Format("20060102T150405Z"))
	header.Add("Accept-Encoding", "identity")
	header.Add("Accept", "application/json")
	header.Add("X-EventHorizon-Request-Hash", requestHash)

	bodyStr := "Action=GetCallerIdentity&Version=2011-06-15\r\n"
	body := io.NopCloser(bytes.NewBuffer([]byte(bodyStr)))
	stsReqBodyHash := HexSha([]byte(bodyStr))

	stsReq := &http.Request{
		Method: "POST",
		URL:    u,
		Header: header,
		Body:   body,
	}

	return stsReq, stsReqBodyHash, nil
}
