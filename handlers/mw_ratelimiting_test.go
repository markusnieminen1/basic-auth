package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterBlocksPerAddressAndResetsAfterTheWindow(t *testing.T) {
	limiter := NewSimpleRateLimiter(2, 50*time.Millisecond)
	handler := limiter.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	status := func(addr string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < 2; i++ {
		if code := status("192.0.2.1:1000"); code != http.StatusOK {
			t.Fatalf("request %d answered %d", i+1, code)
		}
	}
	if code := status("192.0.2.1:2000"); code != http.StatusTooManyRequests {
		t.Errorf("third request from the same address (other port) answered %d, want 429", code)
	}
	if code := status("192.0.2.2:1000"); code != http.StatusOK {
		t.Errorf("another address answered %d, want 200", code)
	}

	time.Sleep(60 * time.Millisecond)
	if code := status("192.0.2.1:1000"); code != http.StatusOK {
		t.Errorf("after the window the address answered %d, want 200", code)
	}
}
