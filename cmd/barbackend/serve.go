package main

import "github.com/gin-gonic/gin"

func serve() error {
	router := gin.Default()
	router.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{
			"message": "pong",
		})
	})
	return router.Run()
}
