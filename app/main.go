package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// HEALTH CHECK & READINESS
// ============================================================================

// HealthChecker interface for custom health checks
type HealthChecker interface {
	Check(ctx context.Context) error
	Name() string
}

// HealthCheck represents a health check result
type HealthCheck struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Checks    map[string]string `json:"checks,omitempty"`
}

// HealthManager manages health and readiness checks
type HealthManager struct {
	checkers []HealthChecker
	mu       sync.RWMutex
	ready    atomic.Bool
}

// NewHealthManager creates a new health manager
func NewHealthManager() *HealthManager {
	hm := &HealthManager{
		checkers: make([]HealthChecker, 0),
	}
	hm.ready.Store(true)
	return hm
}

// AddChecker adds a health checker
func (hm *HealthManager) AddChecker(checker HealthChecker) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.checkers = append(hm.checkers, checker)
}

// SetReady sets the readiness status
func (hm *HealthManager) SetReady(ready bool) {
	hm.ready.Store(ready)
}

// HealthHandler returns health check handler
func (hm *HealthManager) HealthHandler() HandlerFunc {
	return func(ctx *Context) {
		hm.mu.RLock()
		checkers := hm.checkers
		hm.mu.RUnlock()

		result := HealthCheck{
			Status:    "healthy",
			Timestamp: time.Now(),
			Checks:    make(map[string]string),
		}

		for _, checker := range checkers {
			if err := checker.Check(ctx.Context()); err != nil {
				result.Status = "unhealthy"
				result.Checks[checker.Name()] = err.Error()
			} else {
				result.Checks[checker.Name()] = "ok"
			}
		}

		code := http.StatusOK
		if result.Status == "unhealthy" {
			code = http.StatusServiceUnavailable
		}

		ctx.JSON(code, result)
	}
}

// ReadinessHandler returns readiness check handler
func (hm *HealthManager) ReadinessHandler() HandlerFunc {
	return func(ctx *Context) {
		if hm.ready.Load() {
			ctx.JSON(http.StatusOK, map[string]string{"status": "ready"})
		} else {
			ctx.JSON(http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
		}
	}
}

// ============================================================================
// METRICS & MONITORING
// ============================================================================

// Metrics tracks request metrics
type Metrics struct {
	totalRequests   atomic.Uint64
	totalErrors     atomic.Uint64
	activeRequests  atomic.Int64
	requestDuration sync.Map // path -> []time.Duration
	statusCodes     sync.Map // status code -> count
	mu              sync.RWMutex
}

// NewMetrics creates a new metrics instance
func NewMetrics() *Metrics {
	return &Metrics{}
}

// MetricsMiddleware tracks request metrics
func (m *Metrics) MetricsMiddleware() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			start := time.Now()
			m.totalRequests.Add(1)
			m.activeRequests.Add(1)

			defer func() {
				m.activeRequests.Add(-1)
				duration := time.Since(start)

				path := ctx.Request.URL.Path
				durations, _ := m.requestDuration.LoadOrStore(path, &[]time.Duration{})
				durs := durations.(*[]time.Duration)
				*durs = append(*durs, duration)

				// Track status code
				status := http.StatusOK
				if rw, ok := ctx.Writer.(*responseWriter); ok {
					status = rw.status
				}
				count, _ := m.statusCodes.LoadOrStore(status, new(atomic.Uint64))
				count.(*atomic.Uint64).Add(1)

				if status >= 500 {
					m.totalErrors.Add(1)
				}
			}()

			next(ctx)
		}
	}
}

// MetricsHandler returns metrics in JSON format
func (m *Metrics) MetricsHandler() HandlerFunc {
	return func(ctx *Context) {
		metrics := map[string]interface{}{
			"total_requests":  m.totalRequests.Load(),
			"total_errors":    m.totalErrors.Load(),
			"active_requests": m.activeRequests.Load(),
			"status_codes":    make(map[string]uint64),
			"endpoints":       make(map[string]map[string]interface{}),
		}

		m.statusCodes.Range(func(key, value interface{}) bool {
			status := key.(int)
			count := value.(*atomic.Uint64).Load()
			metrics["status_codes"].(map[string]uint64)[fmt.Sprintf("%d", status)] = count
			return true
		})

		m.requestDuration.Range(func(key, value interface{}) bool {
			path := key.(string)
			durations := *value.(*[]time.Duration)
			if len(durations) > 0 {
				var total time.Duration
				for _, d := range durations {
					total += d
				}
				avg := total / time.Duration(len(durations))
				metrics["endpoints"].(map[string]map[string]interface{})[path] = map[string]interface{}{
					"count":  len(durations),
					"avg_ms": avg.Milliseconds(),
				}
			}
			return true
		})

		ctx.JSON(http.StatusOK, metrics)
	}
}

// ============================================================================
// RESPONSE WRITER WRAPPER
// ============================================================================

type responseWriter struct {
	http.ResponseWriter
	status  int
	size    int
	written bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, status: http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.status = code
		rw.ResponseWriter.WriteHeader(code)
		rw.written = true
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}

// ============================================================================
// COMPRESSION MIDDLEWARE
// ============================================================================

type gzipResponseWriter struct {
	http.ResponseWriter
	writer *gzip.Writer
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.writer.Write(b)
}

// Close closes the gzip writer
func (w gzipResponseWriter) Close() error {
	return w.writer.Close()
}

// Compression middleware for gzip compression
func Compression(minSize int) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			// Skip compression for non-compressible content
			if !strings.Contains(ctx.Request.Header.Get("Accept-Encoding"), "gzip") {
				next(ctx)
				return
			}

			// Create a buffer to capture the response
			buf := &bytes.Buffer{}
			gzw := gzip.NewWriter(buf)
			defer gzw.Close()

			// Replace the response writer with our gzip writer
			originalWriter := ctx.Writer
			gzipWriter := gzipResponseWriter{
				ResponseWriter: ctx.Writer,
				writer:         gzw,
			}

			// Set headers for gzip compression
			ctx.Writer.Header().Set("Content-Encoding", "gzip")
			ctx.Writer.Header().Set("Vary", "Accept-Encoding")
			ctx.Writer = gzipWriter

			next(ctx)

			// Close the gzip writer to flush any remaining data
			gzw.Close()

			// Only use compressed response if it meets minimum size
			if buf.Len() >= minSize {
				originalWriter.Header().Set("Content-Encoding", "gzip")
				originalWriter.Header().Del("Content-Length")
				originalWriter.Write(buf.Bytes())
			} else {
				// If too small, write uncompressed but we've already written to buffer
				// So we need to handle this differently
				originalWriter.Header().Del("Content-Encoding")
				originalWriter.Write(buf.Bytes())
			}
		}
	}
}

// ============================================================================
// CIRCUIT BREAKER
// ============================================================================

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	maxFailures  uint32
	resetTimeout time.Duration
	failures     atomic.Uint32
	lastFailTime atomic.Value
	state        atomic.Uint32 // 0: closed, 1: open, 2: half-open
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures uint32, resetTimeout time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
	}
	cb.state.Store(0)
	return cb
}

// Execute executes the handler with circuit breaker
func (cb *CircuitBreaker) Execute(ctx *Context, handler HandlerFunc) error {
	state := cb.state.Load()

	// Check if circuit is open
	if state == 1 {
		lastFail, ok := cb.lastFailTime.Load().(time.Time)
		if ok && time.Since(lastFail) > cb.resetTimeout {
			cb.state.Store(2) // half-open
		} else {
			return errors.New("circuit breaker is open")
		}
	}

	// Execute handler
	done := make(chan bool, 1)
	failed := false

	go func() {
		defer func() {
			if r := recover(); r != nil {
				failed = true
			}
			done <- true
		}()
		handler(ctx)
	}()

	<-done

	if failed {
		cb.recordFailure()
		return errors.New("handler failed")
	}

	if state == 2 {
		cb.reset()
	}

	return nil
}

func (cb *CircuitBreaker) recordFailure() {
	failures := cb.failures.Add(1)
	cb.lastFailTime.Store(time.Now())

	if failures >= cb.maxFailures {
		cb.state.Store(1) // open
	}
}

func (cb *CircuitBreaker) reset() {
	cb.failures.Store(0)
	cb.state.Store(0) // closed
}

// CircuitBreakerMiddleware creates circuit breaker middleware
func CircuitBreakerMiddleware(maxFailures uint32, resetTimeout time.Duration) MiddlewareFunc {
	cb := NewCircuitBreaker(maxFailures, resetTimeout)

	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			if err := cb.Execute(ctx, next); err != nil {
				ctx.JSON(http.StatusServiceUnavailable, map[string]string{
					"error": "Service temporarily unavailable",
				})
			}
		}
	}
}

// ============================================================================
// CACHING
// ============================================================================

// CacheEntry represents a cached response
type CacheEntry struct {
	Data      []byte
	Headers   http.Header
	Status    int
	ExpiresAt time.Time
}

// Cache implements in-memory caching
type Cache struct {
	entries sync.Map
	mu      sync.RWMutex
}

// NewCache creates a new cache
func NewCache() *Cache {
	c := &Cache{}
	go c.cleanup()
	return c
}

func (c *Cache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		c.entries.Range(func(key, value interface{}) bool {
			entry := value.(*CacheEntry)
			if now.After(entry.ExpiresAt) {
				c.entries.Delete(key)
			}
			return true
		})
	}
}

// CacheMiddleware creates caching middleware
func CacheMiddleware(cache *Cache, ttl time.Duration) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			// Only cache GET requests
			if ctx.Request.Method != http.MethodGet {
				next(ctx)
				return
			}

			cacheKey := ctx.Request.URL.Path + "?" + ctx.Request.URL.RawQuery

			// Check cache
			if entry, ok := cache.entries.Load(cacheKey); ok {
				cached := entry.(*CacheEntry)
				if time.Now().Before(cached.ExpiresAt) {
					// Serve from cache
					for k, v := range cached.Headers {
						ctx.Writer.Header()[k] = v
					}
					ctx.Writer.Header().Set("X-Cache", "HIT")
					ctx.Writer.WriteHeader(cached.Status)
					ctx.Writer.Write(cached.Data)
					return
				}
			}

			// Create buffer writer
			buf := &bytes.Buffer{}
			writer := newResponseWriter(ctx.Writer)
			ctx.Writer = writer

			// Create a multi-writer to write to both the original writer and the buffer
			// This is necessary to capture the response for caching
			multiWriter := io.MultiWriter(writer, buf)

			next(ctx)

			// Restore the original writer
			ctx.Writer = writer.ResponseWriter

			// Cache response
			if writer.status == http.StatusOK {
				entry := &CacheEntry{
					Data:      buf.Bytes(),
					Headers:   writer.Header(),
					Status:    writer.status,
					ExpiresAt: time.Now().Add(ttl),
				}
				cache.entries.Store(cacheKey, entry)
			}

			// Write the response to the client
			multiWriter.Write(nil)
		}
	}
}

// ============================================================================
// API KEY AUTHENTICATION
// ============================================================================

// APIKeyAuth middleware for API key authentication
func APIKeyAuth(validKeys map[string]string, headerName string) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			key := ctx.Request.Header.Get(headerName)
			if key == "" {
				ctx.JSON(http.StatusUnauthorized, map[string]string{
					"error": "API key required",
				})
				return
			}

			// Constant-time comparison to prevent timing attacks
			valid := false
			for validKey := range validKeys {
				if subtle.ConstantTimeCompare([]byte(key), []byte(validKey)) == 1 {
					valid = true
					ctx.Set("api_key_user", validKeys[validKey])
					break
				}
			}

			if !valid {
				ctx.JSON(http.StatusUnauthorized, map[string]string{
					"error": "Invalid API key",
				})
				return
			}

			next(ctx)
		}
	}
}

// ============================================================================
// REQUEST VALIDATION
// ============================================================================

// Validator interface for custom validation
type Validator interface {
	Validate() error
}

// ValidateBody middleware validates request body
func ValidateBody() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			if ctx.Request.Method == "POST" || ctx.Request.Method == "PUT" || ctx.Request.Method == "PATCH" {
				contentType := ctx.Request.Header.Get("Content-Type")
				if !strings.Contains(contentType, "application/json") {
					ctx.JSON(http.StatusBadRequest, map[string]string{
						"error": "Content-Type must be application/json",
					})
					return
				}
			}
			next(ctx)
		}
	}
}

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

// GracefulServer extends Server with graceful shutdown
type GracefulServer struct {
	*Server
	shutdownTimeout time.Duration
}

// NewGracefulServer creates a server with graceful shutdown
func NewGracefulServer(addr string, shutdownTimeout time.Duration) *GracefulServer {
	return &GracefulServer{
		Server:          NewServer(addr),
		shutdownTimeout: shutdownTimeout,
	}
}

// RunWithShutdown starts server with graceful shutdown handling
func (gs *GracefulServer) RunWithShutdown(ctx context.Context) error {
	srv := &http.Server{
		Addr:           gs.addr,
		Handler:        gs.router,
		ReadTimeout:    gs.readTimeout,
		WriteTimeout:   gs.writeTimeout,
		MaxHeaderBytes: gs.maxHeaderBytes,
	}

	errChan := make(chan error, 1)
	go func() {
		fmt.Printf("Server starting on %s\n", gs.addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		fmt.Println("Shutting down server gracefully...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), gs.shutdownTimeout)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server forced to shutdown: %w", err)
		}

		fmt.Println("Server stopped")
		return nil
	}
}

// ============================================================================
// SERVICE DISCOVERY
// ============================================================================

// ServiceRegistry manages service instances
type ServiceRegistry struct {
	services sync.Map // service name -> []ServiceInstance
	mu       sync.RWMutex
}

// ServiceInstance represents a service instance
type ServiceInstance struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Address  string            `json:"address"`
	Port     int               `json:"port"`
	Metadata map[string]string `json:"metadata"`
	LastSeen time.Time         `json:"last_seen"`
}

// NewServiceRegistry creates a new service registry
func NewServiceRegistry() *ServiceRegistry {
	sr := &ServiceRegistry{}
	go sr.cleanup()
	return sr
}

func (sr *ServiceRegistry) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		sr.services.Range(func(key, value interface{}) bool {
			instances := value.([]*ServiceInstance)
			filtered := make([]*ServiceInstance, 0)

			for _, inst := range instances {
				if now.Sub(inst.LastSeen) < 60*time.Second {
					filtered = append(filtered, inst)
				}
			}

			if len(filtered) > 0 {
				sr.services.Store(key, filtered)
			} else {
				sr.services.Delete(key)
			}
			return true
		})
	}
}

// Register registers a service instance
func (sr *ServiceRegistry) Register(instance *ServiceInstance) {
	instance.LastSeen = time.Now()

	val, _ := sr.services.LoadOrStore(instance.Name, []*ServiceInstance{})
	instances := val.([]*ServiceInstance)

	// Update or add instance
	found := false
	for i, inst := range instances {
		if inst.ID == instance.ID {
			instances[i] = instance
			found = true
			break
		}
	}

	if !found {
		instances = append(instances, instance)
	}

	sr.services.Store(instance.Name, instances)
}

// Discover returns all instances of a service
func (sr *ServiceRegistry) Discover(serviceName string) []*ServiceInstance {
	val, ok := sr.services.Load(serviceName)
	if !ok {
		return nil
	}
	return val.([]*ServiceInstance)
}

// Deregister removes a service instance
func (sr *ServiceRegistry) Deregister(serviceName, instanceID string) {
	val, ok := sr.services.Load(serviceName)
	if !ok {
		return
	}

	instances := val.([]*ServiceInstance)
	filtered := make([]*ServiceInstance, 0)

	for _, inst := range instances {
		if inst.ID != instanceID {
			filtered = append(filtered, inst)
		}
	}

	if len(filtered) > 0 {
		sr.services.Store(serviceName, filtered)
	} else {
		sr.services.Delete(serviceName)
	}
}
