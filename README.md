[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=agile-security_sigv4util&metric=alert_status&token=8fd69c4bf9036886ddb141d60b9379a218168cfa)](https://sonarcloud.io/summary/new_code?id=agile-security_sigv4util)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=agile-security_sigv4util&metric=coverage&token=8fd69c4bf9036886ddb141d60b9379a218168cfa)](https://sonarcloud.io/summary/new_code?id=agile-security_sigv4util)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=agile-security_sigv4util&metric=bugs&token=8fd69c4bf9036886ddb141d60b9379a218168cfa)](https://sonarcloud.io/summary/new_code?id=agile-security_sigv4util)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=agile-security_sigv4util&metric=code_smells&token=8fd69c4bf9036886ddb141d60b9379a218168cfa)](https://sonarcloud.io/summary/new_code?id=agile-security_sigv4util)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=agile-security_sigv4util&metric=vulnerabilities&token=8fd69c4bf9036886ddb141d60b9379a218168cfa)](https://sonarcloud.io/summary/new_code?id=agile-security_sigv4util)

# sigv4util
Go module used for SigV4 auth in Agile Security services

## Usage
### Client
1. Import the module
```go
import (
	sigv4clientutil "github.com/agile-security/sigv4util/client"
)
```

2. Add the SigV4 auth header to the HTTP request
```go
	err = sigv4clientutil.AddAuthHeaders(ctx, httpReq, c.cfg, c.cfg.Region)
	if err != nil {
		return resp, err
	}
```

See client code in https://github.com/agile-security/metadata for details.

### Server
1. Add authN middleware to the HTTP server. Ex,
```go
package rest

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/agile-security/sigv4util/server/sigv4auth"
	"github.com/gorilla/mux"
)

type contextKey string

const IdentityContextKey contextKey = "identity"

func AuthenticationMiddleware(authenticator sigv4auth.Authenticator, region string, logger *slog.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoker, err := authenticator.Authenticate(r, region, logger)
			if err != nil {
				errorEncoder(r.Context(), err, w)
				return
			}
			rContext := context.WithValue(r.Context(), IdentityContextKey, invoker)
			next.ServeHTTP(w, r.WithContext(rContext))
		})
	}
}

func FromContextIdentity(ctx context.Context) sigv4auth.Invoker {
	value := ctx.Value(IdentityContextKey)
	if value == nil {
		return sigv4auth.Invoker{}
	}
	return value.(sigv4auth.Invoker)
}
```
2. Add authZ middleware to the HTTP server. Ex,
```go
package rest

import (
	"fmt"
	"net/http"

	"github.com/agile-security/sigv4util/server/sigv4auth"
	"github.com/samber/lo"

	"github.com/gorilla/mux"
)

func AuthorizationMiddleware(allowedRoleARNs []string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoker := FromContextIdentity(r.Context())
			if !IsAuthorized(invoker, allowedRoleARNs) {
				errorEncoder(r.Context(), sigv4auth.NewNotAuthorizedError(fmt.Sprintf("role '%s' is not allowed to call API '%s'", invoker.Caller.ARN, r.URL.Path)), w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func IsAuthorized(invoker sigv4auth.Invoker, allowedRoleARNs []string) bool {
	// check if invoker.Caller.ARN is in the list of allowedRoleARNs and return true if it is, false otherwise
	return lo.Contains(allowedRoleARNs, invoker.Caller.ARN)
}
```
See server code in https://github.com/agile-security/metadata-service/tree/main/internal/rest for details.