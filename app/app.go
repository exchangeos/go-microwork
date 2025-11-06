package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// Context provides request-scoped values and utilities
type Context struct {
	Request    *http.Request
	Writer     http.ResponseWriter
	Params     map[string]string
	data       map[string]interface{}
	handlers   []HandlerFunc
	index      int
	mu         sync.RWMutex
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// HandlerFunc defines the handler function signature
type HandlerFunc func(*Context)

// MiddlewareFunc defines middleware function signature
type MiddlewareFunc func(HandlerFunc) HandlerFunc

// NewContext creates a new Context instance
func NewContext(w http.ResponseWriter, r *http.Request) *Context {
	ctx, cancel := context.WithCancel(r.Context())
	return &Context{
		Request:    r,
		Writer:     w,
		Params:     make(map[string]string),
		data:       make(map[string]interface{}),
		handlers:   make([]HandlerFunc, 0),
		index:      -1,
		ctx:        ctx,
		cancelFunc: cancel,
	}
}

// Set stores a value in the context
func (c *Context) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
}

// Get retrieves a value from the context
func (c *Context) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, exists := c.data[key]
	return val, exists
}

// Context returns the underlying context.Context
func (c *Context) Context() context.Context {
	return c.ctx
}

// Next executes the next handler in the chain
func (c *Context) Next() {
	c.index++
	if c.index < len(c.handlers) {
		c.handlers[c.index](c)
	}
}

// Abort stops the handler chain
func (c *Context) Abort() {
	c.index = len(c.handlers)
}

// JSON sends a JSON response
func (c *Context) JSON(code int, obj interface{}) error {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(code)
	encoder := json.NewEncoder(c.Writer)
	return encoder.Encode(obj)
}

// String sends a plain text response
func (c *Context) String(code int, format string, values ...interface{}) error {
	c.Writer.Header().Set("Content-Type", "text/plain")
	c.Writer.WriteHeader(code)
	_, err := fmt.Fprintf(c.Writer, format, values...)
	return err
}

// Bind parses request body into the provided struct
func (c *Context) Bind(obj interface{}) error {
	decoder := json.NewDecoder(c.Request.Body)
	return decoder.Decode(obj)
}

// Query returns the query parameter value
func (c *Context) Query(key string) string {
	return c.Request.URL.Query().Get(key)
}

// QueryDefault returns query parameter with default value
func (c *Context) QueryDefault(key, defaultValue string) string {
	if val := c.Query(key); val != "" {
		return val
	}
	return defaultValue
}

// Param returns the URL parameter value
func (c *Context) Param(key string) string {
	return c.Params[key]
}

// Status sets the HTTP status code
func (c *Context) Status(code int) {
	c.Writer.WriteHeader(code)
}

// Router handles HTTP routing with pattern matching
type Router struct {
	routes     map[string][]*Route
	middleware []MiddlewareFunc
	notFound   HandlerFunc
	mu         sync.RWMutex
	pool       sync.Pool
}

// Route represents a single route
type Route struct {
	method  string
	pattern string
	regex   *regexp.Regexp
	params  []string
	handler HandlerFunc
}

// NewRouter creates a new Router instance
func NewRouter() *Router {
	r := &Router{
		routes:   make(map[string][]*Route),
		notFound: defaultNotFoundHandler,
	}
	r.pool.New = func() interface{} {
		return &Context{
			Params: make(map[string]string),
			data:   make(map[string]interface{}),
		}
	}
	return r
}

// Use adds global middleware
func (r *Router) Use(middleware ...MiddlewareFunc) {
	r.middleware = append(r.middleware, middleware...)
}

// GET registers a GET route
func (r *Router) GET(pattern string, handler HandlerFunc) {
	r.addRoute("GET", pattern, handler)
}

// POST registers a POST route
func (r *Router) POST(pattern string, handler HandlerFunc) {
	r.addRoute("POST", pattern, handler)
}

// PUT registers a PUT route
func (r *Router) PUT(pattern string, handler HandlerFunc) {
	r.addRoute("PUT", pattern, handler)
}

// DELETE registers a DELETE route
func (r *Router) DELETE(pattern string, handler HandlerFunc) {
	r.addRoute("DELETE", pattern, handler)
}

// PATCH registers a PATCH route
func (r *Router) PATCH(pattern string, handler HandlerFunc) {
	r.addRoute("PATCH", pattern, handler)
}

// addRoute adds a route to the router
func (r *Router) addRoute(method, pattern string, handler HandlerFunc) {
	route := &Route{
		method:  method,
		pattern: pattern,
		handler: handler,
	}

	// Parse pattern for parameters
	paramRegex := regexp.MustCompile(`:(\w+)`)
	params := paramRegex.FindAllStringSubmatch(pattern, -1)

	for _, param := range params {
		route.params = append(route.params, param[1])
	}

	// Convert pattern to regex
	regexPattern := paramRegex.ReplaceAllString(pattern, `([^/]+)`)
	regexPattern = "^" + regexPattern + "$"
	route.regex = regexp.MustCompile(regexPattern)

	r.mu.Lock()
	r.routes[method] = append(r.routes[method], route)
	r.mu.Unlock()
}

// SetNotFound sets custom 404 handler
func (r *Router) SetNotFound(handler HandlerFunc) {
	r.notFound = handler
}

// ServeHTTP implements http.Handler interface
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := r.pool.Get().(*Context)
	ctx.Request = req
	ctx.Writer = w
	// ctx.Params = ctx.Params[:0] // clear slice
	ctx.index = -1
	ctx.handlers = ctx.handlers[:0]
	ctx.ctx, ctx.cancelFunc = context.WithCancel(req.Context())

	// Clear maps
	for k := range ctx.Params {
		delete(ctx.Params, k)
	}
	for k := range ctx.data {
		delete(ctx.data, k)
	}

	defer r.pool.Put(ctx)
	defer func() {
		if ctx.cancelFunc != nil {
			ctx.cancelFunc()
		}
	}()

	r.mu.RLock()
	routes := r.routes[req.Method]
	r.mu.RUnlock()

	var matchedRoute *Route
	for _, route := range routes {
		matches := route.regex.FindStringSubmatch(req.URL.Path)
		if matches != nil {
			matchedRoute = route
			for i, param := range route.params {
				ctx.Params[param] = matches[i+1]
			}
			break
		}
	}

	if matchedRoute == nil {
		r.notFound(ctx)
		return
	}

	// Build handler chain with middleware
	finalHandler := matchedRoute.handler
	for i := len(r.middleware) - 1; i >= 0; i-- {
		finalHandler = r.middleware[i](finalHandler)
	}

	ctx.handlers = append(ctx.handlers, finalHandler)
	ctx.Next()
}

// defaultNotFoundHandler is the default 404 handler
func defaultNotFoundHandler(ctx *Context) {
	ctx.JSON(404, map[string]string{"error": "Not Found"})
}

// Group represents a route group with shared prefix and middleware
type Group struct {
	router     *Router
	prefix     string
	middleware []MiddlewareFunc
}

// Group creates a new route group
func (r *Router) Group(prefix string, middleware ...MiddlewareFunc) *Group {
	return &Group{
		router:     r,
		prefix:     prefix,
		middleware: middleware,
	}
}

// Use adds middleware to the group
func (g *Group) Use(middleware ...MiddlewareFunc) {
	g.middleware = append(g.middleware, middleware...)
}

// GET registers a GET route in the group
func (g *Group) GET(pattern string, handler HandlerFunc) {
	g.addRoute("GET", pattern, handler)
}

// POST registers a POST route in the group
func (g *Group) POST(pattern string, handler HandlerFunc) {
	g.addRoute("POST", pattern, handler)
}

// PUT registers a PUT route in the group
func (g *Group) PUT(pattern string, handler HandlerFunc) {
	g.addRoute("PUT", pattern, handler)
}

// DELETE registers a DELETE route in the group
func (g *Group) DELETE(pattern string, handler HandlerFunc) {
	g.addRoute("DELETE", pattern, handler)
}

// PATCH registers a PATCH route in the group
func (g *Group) PATCH(pattern string, handler HandlerFunc) {
	g.addRoute("PATCH", pattern, handler)
}

// addRoute adds a route to the group
func (g *Group) addRoute(method, pattern string, handler HandlerFunc) {
	fullPattern := g.prefix + pattern

	// Wrap handler with group middleware
	finalHandler := handler
	for i := len(g.middleware) - 1; i >= 0; i-- {
		finalHandler = g.middleware[i](finalHandler)
	}

	g.router.addRoute(method, fullPattern, finalHandler)
}

// Server wraps the router with additional features
type Server struct {
	router         *Router
	addr           string
	readTimeout    time.Duration
	writeTimeout   time.Duration
	maxHeaderBytes int
}

// NewServer creates a new Server instance
func NewServer(addr string) *Server {
	return &Server{
		router:         NewRouter(),
		addr:           addr,
		readTimeout:    30 * time.Second,
		writeTimeout:   30 * time.Second,
		maxHeaderBytes: 1 << 20, // 1 MB
	}
}

// Router returns the underlying router
func (s *Server) Router() *Router {
	return s.router
}

// SetTimeouts configures read and write timeouts
func (s *Server) SetTimeouts(read, write time.Duration) {
	s.readTimeout = read
	s.writeTimeout = write
}

// Run starts the HTTP server
func (s *Server) Run() error {
	srv := &http.Server{
		Addr:           s.addr,
		Handler:        s.router,
		ReadTimeout:    s.readTimeout,
		WriteTimeout:   s.writeTimeout,
		MaxHeaderBytes: s.maxHeaderBytes,
	}

	fmt.Printf("Server starting on %s\n", s.addr)
	return srv.ListenAndServe()
}

// Built-in Middleware

// Logger middleware logs request details
func Logger() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			start := time.Now()
			path := ctx.Request.URL.Path
			method := ctx.Request.Method

			next(ctx)

			latency := time.Since(start)
			fmt.Printf("[%s] %s %s - %v\n", method, path, ctx.Request.RemoteAddr, latency)
		}
	}
}

// Recovery middleware recovers from panics
func Recovery() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			defer func() {
				if err := recover(); err != nil {
					fmt.Printf("Panic recovered: %v\n", err)
					ctx.JSON(500, map[string]string{"error": "Internal Server Error"})
				}
			}()
			next(ctx)
		}
	}
}

// CORS middleware handles Cross-Origin Resource Sharing
func CORS(allowOrigin, allowMethods, allowHeaders string) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			ctx.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			ctx.Writer.Header().Set("Access-Control-Allow-Methods", allowMethods)
			ctx.Writer.Header().Set("Access-Control-Allow-Headers", allowHeaders)

			if ctx.Request.Method == "OPTIONS" {
				ctx.Status(204)
				return
			}

			next(ctx)
		}
	}
}

// RateLimiter creates a simple rate limiting middleware
func RateLimiter(maxRequests int, window time.Duration) MiddlewareFunc {
	type client struct {
		count     int
		resetTime time.Time
	}

	clients := make(map[string]*client)
	var mu sync.Mutex

	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			ip := ctx.Request.RemoteAddr

			mu.Lock()
			c, exists := clients[ip]
			now := time.Now()

			if !exists || now.After(c.resetTime) {
				clients[ip] = &client{
					count:     1,
					resetTime: now.Add(window),
				}
				mu.Unlock()
				next(ctx)
				return
			}

			if c.count >= maxRequests {
				mu.Unlock()
				ctx.JSON(429, map[string]string{"error": "Too Many Requests"})
				return
			}

			c.count++
			mu.Unlock()
			next(ctx)
		}
	}
}

// BasicAuth middleware provides HTTP basic authentication
func BasicAuth(username, password string) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			user, pass, ok := ctx.Request.BasicAuth()
			if !ok || user != username || pass != password {
				ctx.Writer.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				ctx.JSON(401, map[string]string{"error": "Unauthorized"})
				return
			}
			next(ctx)
		}
	}
}

// BodyLimit middleware limits request body size
func BodyLimit(maxBytes int64) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxBytes)
			next(ctx)
		}
	}
}

// RequestID middleware adds a unique request ID
func RequestID() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			requestID := fmt.Sprintf("%d", time.Now().UnixNano())
			ctx.Set("RequestID", requestID)
			ctx.Writer.Header().Set("X-Request-ID", requestID)
			next(ctx)
		}
	}
}

// Timeout middleware adds request timeout
func Timeout(timeout time.Duration) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			done := make(chan struct{})

			go func() {
				next(ctx)
				close(done)
			}()

			select {
			case <-done:
				return
			case <-time.After(timeout):
				ctx.JSON(504, map[string]string{"error": "Request Timeout"})
			}
		}
	}
}

// // Example usage demonstration
// func ExampleUsage() {
// 	// Create server
// 	server := NewServer(":8080")
// 	router := server.Router()

// 	// Global middleware
// 	router.Use(Logger())
// 	router.Use(Recovery())
// 	router.Use(RequestID())

// 	// Routes
// 	router.GET("/", func(ctx *Context) {
// 		ctx.JSON(200, map[string]string{"message": "Welcome to the API"})
// 	})

// 	router.GET("/hello/:name", func(ctx *Context) {
// 		name := ctx.Param("name")
// 		ctx.JSON(200, map[string]string{"message": "Hello, " + name})
// 	})

// 	// API group with authentication
// 	api := router.Group("/api/v1", BasicAuth("admin", "secret"))

// 	api.GET("/users", func(ctx *Context) {
// 		ctx.JSON(200, []string{"user1", "user2", "user3"})
// 	})

// 	api.POST("/users", func(ctx *Context) {
// 		var user struct {
// 			Name  string `json:"name"`
// 			Email string `json:"email"`
// 		}

// 		if err := ctx.Bind(&user); err != nil {
// 			ctx.JSON(400, map[string]string{"error": "Invalid request"})
// 			return
// 		}

// 		ctx.JSON(201, user)
// 	})

// 	// Start server
// 	server.Run()
// }
