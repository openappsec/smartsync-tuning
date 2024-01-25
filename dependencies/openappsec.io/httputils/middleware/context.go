package middleware

import (
	"fmt"
	"net/http"

	"openappsec.io/ctxutils"
	"openappsec.io/httputils/responses"
	"openappsec.io/log"
)

const (
	// header key const
	headerKeyAgentID        = "X-Agent-Id"
	headerKeyTenantID       = "X-Tenant-Id"
	headerKeyTraceID        = "X-Trace-Id"
	headerKeySourceID       = "X-Source-Id"
	headerKeyProfileID      = "X-Profile-Id"
	headerKeyCorrelationID  = "X-Correlation-Id"
	headerKeyRequestID      = "X-Request-Id"
	headerKeyUserID         = "X-User-Id"
	headerKeyCallingService = "X-Calling-Service"
)

// TenantID is a middleware that injects a tenant ID into the context of each request.
func TenantID(errMsg string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return HeaderToContext(next, headerKeyTenantID, ctxutils.ContextKeyTenantID, true, errMsg)
	}
}

// SourceID is a middleware that injects a source ID into the context of each request.
func SourceID(errMsg string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return HeaderToContext(next, headerKeySourceID, ctxutils.ContextKeySourceID, true, errMsg)
	}
}

// AgentID is a middleware that injects an agent ID into the context of each request.
func AgentID(errMsg string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return HeaderToContext(next, headerKeyAgentID, ctxutils.ContextKeyAgentID, true, errMsg)
	}
}

// ProfileID is a middleware that injects an profile ID into the context of each request.
func ProfileID(errMsg string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return HeaderToContext(next, headerKeyProfileID, ctxutils.ContextKeyProfileID, true, errMsg)
	}
}

// UserID is a middleware that injects a user ID into the context of each request.
func UserID(errMsg string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return HeaderToContext(next, headerKeyUserID, ctxutils.ContextKeyUserID, true, errMsg)
	}
}

// CallingService is a middleware that injects the callingService into the context of each request.
func CallingService(errMsg string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return HeaderToContext(next, headerKeyCallingService, ctxutils.ContextKeyCallingService, false, errMsg)
	}
}

// CorrelationID is a middleware that injects an correlation ID into the context of each request.
// First it looks for the X-Trace-Id header. If it doesn't exist, it uses the X-Correlation-Id header.
// If the latter doesn't exist as well, it uses the Request-Id header.
// The default value found is set in context to both the correlationID and traceID
// It's an optional middleware - if the client doesn't send the header it won't fail
func CorrelationID(errMsg string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			id := r.Header.Get(headerKeyTraceID)
			if id == "" {
				id = r.Header.Get(headerKeyCorrelationID)
				if id == "" {
					id = r.Header.Get(headerKeyRequestID)
				}
			}

			ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyEventTraceID, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequestID is a middleware that injects an request ID into the context of each request.
// It's an optional middleware - if the client doesn't send the header it won't fail
func RequestID(errMsg string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return HeaderToContext(next, headerKeyRequestID, ctxutils.ContextKeyRequestID, false, errMsg)
	}
}

// HeaderToContext is a middleware that extracts a requested header value and injects it into the context under the given key.
// strict specifies whether to fail should the requested header not exist
func HeaderToContext(next http.Handler, headerKey string, contextKey string, strict bool, errMsg string) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		id := r.Header.Get(headerKey)
		if id == "" && strict {
			msg := fmt.Sprintf("Invalid request headers. Missing %s request header", headerKey)
			log.WithContext(r.Context()).Error(msg)
			responses.HTTPReturn(ctx, w, http.StatusBadRequest, []byte(errMsg), true)
			return
		}

		ctx = ctxutils.Insert(ctx, contextKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}
