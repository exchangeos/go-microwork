package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/exchangeos/go-microwork/app"
)

// ============================================================================
// EXAMPLE MODELS
// ============================================================================

type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

func (r *CreateUserRequest) Validate() error {
	if r.Username == "" {
		return fmt.Errorf("username is required")
	}
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	return nil
}

// ============================================================================
// CUSTOM HEALTH CHECKER
// ============================================================================

type DatabaseHealthChecker struct {
	// In real app, you'd have a DB connection here
}

func (d *DatabaseHealthChecker) Check(ctx context.Context) error {
	// Simulate database health check
	// In real app: return db.PingContext(ctx)
	return nil // healthy
}

func (d *DatabaseHealthChecker) Name() string {
	return "database"
}

type RedisHealthChecker struct{}

func (r *RedisHealthChecker) Check(ctx context.Context) error {
	// Simulate Redis health check
	return nil
}

func (r *RedisHealthChecker) Name() string {
	return "redis"
}

// ============================================================================
// MAIN APPLICATION
// ============================================================================

func main() {
	// Create graceful server with 30s shutdown timeout
	server := app.NewGracefulServer(":8080", 30*time.Second)
	router := server.Router()

	// ========================================================================
	// SETUP INFRASTRUCTURE COMPONENTS
	// ========================================================================

	// Health Manager
	healthManager := app.NewHealthManager()
	healthManager.AddChecker(&DatabaseHealthChecker{})
	healthManager.AddChecker(&RedisHealthChecker{})

	// Metrics
	metrics := app.NewMetrics()

	// // Cache
	// cache := app.NewCache()

	// Service Registry
	registry := app.NewServiceRegistry()

	// Register this service instance
	registry.Register(&app.ServiceInstance{
		ID:      "api-server-1",
		Name:    "api-service",
		Address: "localhost",
		Port:    8080,
		Metadata: map[string]string{
			"version": "1.0.0",
			"region":  "us-east-1",
		},
	})

	// ========================================================================
	// GLOBAL MIDDLEWARE
	// ========================================================================

	router.Use(app.Recovery())                            // Panic recovery
	router.Use(app.Logger())                              // Request logging
	router.Use(metrics.MetricsMiddleware())               // Metrics tracking
	router.Use(app.RequestID())                           // Add request IDs
	router.Use(app.CORS("*", "GET,POST,PUT,DELETE", "*")) // CORS
	router.Use(app.BodyLimit(1024 * 1024))                // 1MB body limit

	// ========================================================================
	// HEALTH & MONITORING ENDPOINTS
	// ========================================================================

	router.GET("/health", healthManager.HealthHandler())
	router.GET("/ready", healthManager.ReadinessHandler())
	router.GET("/metrics", metrics.MetricsHandler())

	// ========================================================================
	// SERVICE DISCOVERY ENDPOINTS
	// ========================================================================

	router.GET("/services/:name", func(ctx *app.Context) {
		serviceName := ctx.Param("name")
		instances := registry.Discover(serviceName)

		if instances == nil {
			ctx.JSON(404, map[string]string{
				"error": "service not found",
			})
			return
		}

		ctx.JSON(200, map[string]interface{}{
			"service":   serviceName,
			"instances": instances,
		})
	})

	router.POST("/services/register", func(ctx *app.Context) {
		var instance app.ServiceInstance
		if err := ctx.Bind(&instance); err != nil {
			ctx.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		registry.Register(&instance)
		ctx.JSON(200, map[string]string{"status": "registered"})
	})

	// ========================================================================
	// PUBLIC API GROUP (with rate limiting)
	// ========================================================================

	publicAPI := router.Group("/api/v1",
		app.RateLimiter(100, 1*time.Minute), // 100 req/min
	)

	// Simple GET endpoint (cached)
	publicAPI.GET("/status", func(ctx *app.Context) {
		ctx.JSON(200, map[string]interface{}{
			"status":    "online",
			"timestamp": time.Now().Unix(),
			"version":   "1.0.0",
		})
	})

	// List users (with caching)
	publicAPI.GET("/users", func(ctx *app.Context) {
		users := []User{
			{
				ID:        "1",
				Username:  "john_doe",
				Email:     "john@example.com",
				CreatedAt: time.Now().Add(-24 * time.Hour),
			},
			{
				ID:        "2",
				Username:  "jane_smith",
				Email:     "jane@example.com",
				CreatedAt: time.Now().Add(-48 * time.Hour),
			},
		}

		ctx.JSON(200, map[string]interface{}{
			"users": users,
			"total": len(users),
		})
	})

	// Get user by ID
	publicAPI.GET("/users/:id", func(ctx *app.Context) {
		userID := ctx.Param("id")

		user := User{
			ID:        userID,
			Username:  "john_doe",
			Email:     "john@example.com",
			CreatedAt: time.Now().Add(-24 * time.Hour),
		}

		ctx.JSON(200, user)
	})

	// ========================================================================
	// PROTECTED API GROUP (with API key auth + validation)
	// ========================================================================

	apiKeys := map[string]string{
		"key_12345": "service_a",
		"key_67890": "service_b",
	}

	protectedAPI := router.Group("/api/v1/admin",
		app.APIKeyAuth(apiKeys, "X-API-Key"),
		app.ValidateBody(),
		app.CircuitBreakerMiddleware(5, 30*time.Second),
	)

	// Create user
	protectedAPI.POST("/users", func(ctx *app.Context) {
		var req CreateUserRequest
		if err := ctx.Bind(&req); err != nil {
			ctx.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		if err := req.Validate(); err != nil {
			ctx.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		user := User{
			ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
			Username:  req.Username,
			Email:     req.Email,
			CreatedAt: time.Now(),
		}

		// Get the service name from context (set by API key middleware)
		apiKeyUser, _ := ctx.Get("api_key_user")

		ctx.JSON(201, map[string]interface{}{
			"user":       user,
			"created_by": apiKeyUser,
		})
	})

	// Update user
	protectedAPI.PUT("/users/:id", func(ctx *app.Context) {
		userID := ctx.Param("id")

		var req CreateUserRequest
		if err := ctx.Bind(&req); err != nil {
			ctx.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		user := User{
			ID:        userID,
			Username:  req.Username,
			Email:     req.Email,
			CreatedAt: time.Now().Add(-24 * time.Hour),
		}

		ctx.JSON(200, user)
	})

	// Delete user
	protectedAPI.DELETE("/users/:id", func(ctx *app.Context) {
		userID := ctx.Param("id")
		ctx.JSON(200, map[string]string{
			"message": fmt.Sprintf("User %s deleted", userID),
		})
	})

	// ========================================================================
	// INTERNAL API GROUP (with basic auth + timeout)
	// ========================================================================

	internalAPI := router.Group("/internal",
		app.BasicAuth("admin", "secret123"),
		app.Timeout(5*time.Second),
	)

	internalAPI.POST("/cache/clear", func(ctx *app.Context) {
		// Clear cache logic here
		ctx.JSON(200, map[string]string{"status": "cache cleared"})
	})

	internalAPI.POST("/readiness/toggle", func(ctx *app.Context) {
		type ReadinessRequest struct {
			Ready bool `json:"ready"`
		}

		var req ReadinessRequest
		if err := ctx.Bind(&req); err != nil {
			ctx.JSON(400, map[string]string{"error": "invalid request"})
			return
		}

		healthManager.SetReady(req.Ready)
		ctx.JSON(200, map[string]string{
			"status": fmt.Sprintf("readiness set to %v", req.Ready),
		})
	})

	// ========================================================================
	// EXAMPLE: CHAINING MULTIPLE ENDPOINTS WITH QUERY PARAMS
	// ========================================================================

	publicAPI.GET("/search", func(ctx *app.Context) {
		query := ctx.QueryDefault("q", "")
		page := ctx.QueryDefault("page", "1")
		limit := ctx.QueryDefault("limit", "10")

		ctx.JSON(200, map[string]interface{}{
			"query":   query,
			"page":    page,
			"limit":   limit,
			"results": []string{"result1", "result2"},
		})
	})

	// ========================================================================
	// EXAMPLE: LONG RUNNING OPERATION WITH CONTEXT
	// ========================================================================

	publicAPI.POST("/process", func(ctx *app.Context) {
		// Simulate long operation that respects context
		select {
		case <-time.After(2 * time.Second):
			ctx.JSON(200, map[string]string{
				"status": "processing complete",
			})
		case <-ctx.Context().Done():
			ctx.JSON(499, map[string]string{
				"error": "client disconnected",
			})
		}
	})

	// ========================================================================
	// CUSTOM 404 HANDLER
	// ========================================================================

	router.SetNotFound(func(ctx *app.Context) {
		ctx.JSON(404, map[string]interface{}{
			"error":   "endpoint not found",
			"path":    ctx.Request.URL.Path,
			"method":  ctx.Request.Method,
			"message": "check API documentation for available endpoints",
		})
	})

	// ========================================================================
	// GRACEFUL SHUTDOWN
	// ========================================================================

	// Create context that listens for interrupt signals
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Print available endpoints
	fmt.Println("\n=== Server Started ===")
	fmt.Println("\nPublic Endpoints:")
	fmt.Println("  GET  http://localhost:8080/health")
	fmt.Println("  GET  http://localhost:8080/ready")
	fmt.Println("  GET  http://localhost:8080/metrics")
	fmt.Println("  GET  http://localhost:8080/api/v1/status")
	fmt.Println("  GET  http://localhost:8080/api/v1/users")
	fmt.Println("  GET  http://localhost:8080/api/v1/users/:id")
	fmt.Println("  GET  http://localhost:8080/api/v1/search?q=test")
	fmt.Println("\nProtected Endpoints (require X-API-Key header):")
	fmt.Println("  POST http://localhost:8080/api/v1/admin/users")
	fmt.Println("  PUT  http://localhost:8080/api/v1/admin/users/:id")
	fmt.Println("  DELETE http://localhost:8080/api/v1/admin/users/:id")
	fmt.Println("\nInternal Endpoints (require Basic Auth: admin/secret123):")
	fmt.Println("  POST http://localhost:8080/internal/cache/clear")
	fmt.Println("  POST http://localhost:8080/internal/readiness/toggle")
	fmt.Println("\nService Discovery:")
	fmt.Println("  GET  http://localhost:8080/services/:name")
	fmt.Println("  POST http://localhost:8080/services/register")
	fmt.Println("\nPress Ctrl+C for graceful shutdown\n")

	// Start server with graceful shutdown
	if err := server.RunWithShutdown(ctx); err != nil {
		log.Fatal(err)
	}
}
