package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/markusnieminen1/basic-auth/domain/customerrors"
)

type SimpleRateLimiter struct {
	mu       sync.Mutex
	requests map[string]int
	window   time.Duration
	maxHits  int
}

func NewSimpleRateLimiter(maxHits int, window time.Duration) *SimpleRateLimiter {
	rl := &SimpleRateLimiter{
		requests: make(map[string]int),
		window:   window,
		maxHits:  maxHits,
	}

	go func() {
		for {
			time.Sleep(rl.window)
			rl.mu.Lock()
			rl.requests = make(map[string]int)
			rl.mu.Unlock()
		}
	}()

	return rl
}

func (rl *SimpleRateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ip, _, err := net.SplitHostPort(r.RemoteAddr)

		if err != nil {
			ip = r.RemoteAddr
		}
		rl.mu.Lock()

		count := rl.requests[ip]

		if count >= rl.maxHits {
			rl.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(customerrors.ErrTooManyRequests)
			return
		}

		rl.requests[ip] = count + 1
		rl.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}
