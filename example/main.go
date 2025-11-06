package main

import "github.com/exchangeos/go-microwork/app"

func main() {
	server := app.NewServer(":8080")
	router := server.Router()

	// Global middleware
	router.Use(app.Logger(), app.Recovery())

	// Simple route
	router.GET("/hello/:name", func(ctx *app.Context) {
		ctx.JSON(200, map[string]string{
			"message": "Hello, " + ctx.Param("name"),
			"User-Agent": ctx.Request.Header.Get("User-Agent"),
			"Authorization": ctx.Request.Header.Get("Authorization"),
		})
	})

	// Protected API group
	api := router.Group("/api/v1", app.BasicAuth("user", "pass"))
	api.POST("/users", func(ctx *app.Context) {
		ctx.JSON(200, map[string]string{
			"message": "User created",
		})
	})

	server.Run()
}
