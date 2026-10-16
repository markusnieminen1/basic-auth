package handlers

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/markusnieminen1/basic-auth/domain/customerrors"
)

// SimpleRateLimiter allows maxHits requests per remote address in each fixed window.
// It keeps its counters in memory, so the limit is per process.
type SimpleRateLimiter struct {
	mu          sync.Mutex
	requests    map[string]int
	windowStart time.Time
	window      time.Duration
	maxHits     int
}

func NewSimpleRateLimiter(maxHits int, window time.Duration) *SimpleRateLimiter {
	return &SimpleRateLimiter{
		requests:    make(map[string]int),
		windowStart: time.Now(),
		window:      window,
		maxHits:     maxHits,
	}
}

// allow counts one request from ip and reports whether it is within the limit.
// The counters are cleared lazily when a request arrives after the window ended,
// so the limiter needs no background goroutine that could never be stopped.
func (rl *SimpleRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if now := time.Now(); now.Sub(rl.windowStart) >= rl.window {
		rl.requests = make(map[string]int)
		rl.windowStart = now
	}
	if rl.requests[ip] >= rl.maxHits {
		return false
	}
	rl.requests[ip]++
	return true
}

func (rl *SimpleRateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !rl.allow(ip) {
			WriteErrorHttp(w, customerrors.ErrTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
