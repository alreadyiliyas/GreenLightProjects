package main

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

func (app *application) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.Header().Set("Connection", "close")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (app *application) rateLimit(next http.Handler) http.Handler {
	
	
	type client struct {
		limiter *rate.Limiter
		lastSeen time.Time
	}
	
	var (
		mu      sync.Mutex
		clients = make(map[string]*client)
	)

	go func() {
		for {
			time.Sleep(time.Minute)

			mu.Lock()

			for ip, client := range clients {
				if time.Since(client.lastSeen) > 3*time.Minute {
					delete(clients, ip)
				}
			}

			mu.Unlock()
		}
	}()

	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if app.config.limiter.enabled {
			IP, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				app.serverErrorResponse(w, r, err)
				return
			}
	
			mu.Lock()
	
			if _, found := clients[IP]; !found {
				clients[IP] = &client{
					limiter: rate.NewLimiter(rate.Limit(app.config.limiter.rps), app.config.limiter.burst),
				}
			}
	
			clients[IP].lastSeen = time.Now()
	
			if !clients[IP].limiter.Allow() {
				mu.Unlock()
				app.rateLimitExceededResponse(w, r)
				return
			}
	
			mu.Unlock()
		}
		
		next.ServeHTTP(w, r)
	})
}
