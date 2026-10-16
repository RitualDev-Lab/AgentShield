package agentshield

import (
	"bytes"
	"context"
	"io"
	"net/http"
)

// HTTPMiddleware creates a standard net/http middleware that redacts credentials
// from incoming HTTP request bodies before reaching your handlers.
func HTTPMiddleware(client *Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read request body", http.StatusBadRequest)
				return
			}
			_ = r.Body.Close()

			if len(bodyBytes) > 0 {
				redactRes, err := client.ScanAndRedact(r.Context(), string(bodyBytes))
				if err == nil && redactRes.HasSecrets {
					bodyBytes = []byte(redactRes.SanitizedText)
				}
			}

			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			r.ContentLength = int64(len(bodyBytes))
			next.ServeHTTP(w, r)
		})
	}
}
