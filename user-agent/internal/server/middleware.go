package server

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

// IPFilter provides IP-based access control.
type IPFilter struct {
	nets     []*net.IPNet
	exactIPs map[string]bool
	allowAll bool
}

// NewIPFilter creates a new IP filter from a list of allowed IPs/CIDRs.
func NewIPFilter(allowed []string) (*IPFilter, error) {
	f := &IPFilter{
		nets:     make([]*net.IPNet, 0, len(allowed)),
		exactIPs: make(map[string]bool),
	}

	if len(allowed) == 0 {
		f.allowAll = true
		log.Println("[WARNING] IP filter is empty - allowing all IPs (not recommended)")
		return f, nil
	}

	for _, cidr := range allowed {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		// Check if it's a single IP (no /mask)
		if !strings.Contains(cidr, "/") {
			f.exactIPs[cidr] = true
			continue
		}

		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %s: %w", cidr, err)
		}
		f.nets = append(f.nets, ipnet)
	}

	return f, nil
}

// Allowed checks if an IP address is allowed.
func (f *IPFilter) Allowed(remoteAddr string) bool {
	if f.allowAll {
		return true
	}

	// Extract IP from remote address (remove port)
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If no port, try as-is
		host = remoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Check exact match
	if f.exactIPs[ip.String()] {
		return true
	}

	// Check CIDR ranges
	for _, ipnet := range f.nets {
		if ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

// IPFilterMiddleware returns a middleware that filters by IP.
func IPFilterMiddleware(f *IPFilter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteAddr := r.RemoteAddr
			if !f.Allowed(remoteAddr) {
				log.Printf("[DENY] IP %s attempted to access %s", remoteAddr, r.URL.Path)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TokenAuthMiddleware provides token-based authentication.
type TokenAuthMiddleware struct {
	token string
}

// NewTokenAuthMiddleware creates a new token auth middleware.
func NewTokenAuthMiddleware(token string) *TokenAuthMiddleware {
	return &TokenAuthMiddleware{token: token}
}

// Middleware returns a middleware that checks auth token.
func (t *TokenAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip if no token configured
		if t.token == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Allow health endpoint without token
		if r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}

		token := r.Header.Get("X-Auth-Token")
		if token == "" {
			log.Printf("[DENY] Missing auth token from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if token != t.token {
			log.Printf("[DENY] Invalid auth token from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RunAsTokenMiddleware provides token authentication for /api/run-as endpoint.
// Uses crypto/subtle.ConstantTimeCompare to prevent timing attacks.
func RunAsTokenMiddleware(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If token is empty, run-as is disabled
			if token == "" {
				log.Printf("[DENY] /api/run-as is disabled (no token configured) from %s", r.RemoteAddr)
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
				return
			}

			provided := r.Header.Get("X-Run-As-Token")
			if provided == "" {
				log.Printf("[DENY] Missing X-Run-As-Token from %s", r.RemoteAddr)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// Use ConstantTimeCompare to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
				log.Printf("[DENY] Invalid X-Run-As-Token from %s", r.RemoteAddr)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}