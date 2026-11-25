package agentshield

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJsonUnmarshalTypes(t *testing.T) {
	payload := `{"hasSecrets":true,"sanitizedText":"token=[AGENT_SHIELD:AI:1]","redactedCount":1,"findings":[{"patternId":"ai-key","severity":"high"}]}`
	var res RedactResult
	if err := json.Unmarshal([]byte(payload), &res); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.HasSecrets || res.RedactedCount != 1 || len(res.Findings) != 1 {
		t.Fatalf("unexpected parsed result: %+v", res)
	}
}

func TestHTTPMiddlewareAllowsSafeGet(t *testing.T) {
	called := false
	handler := HTTPMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called || rec.Code != http.StatusOK {
		t.Fatalf("expected GET passthrough, called=%v status=%d", called, rec.Code)
	}

	reqHead := httptest.NewRequest(http.MethodHead, "/health", strings.NewReader(""))
	recHead := httptest.NewRecorder()
	handler.ServeHTTP(recHead, reqHead)
	if recHead.Code != http.StatusOK {
		t.Fatalf("expected HEAD passthrough, status=%d", recHead.Code)
	}
}
