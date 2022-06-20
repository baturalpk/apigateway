package main

import (
	"log"

	"github.com/baturalpk/apigateway"
)

func main() {
	apigateway.PrepareConfigFile("config", []string{"./examples", "."})
	config, err := apigateway.NewConfig()
	if err != nil {
		log.Fatalln(err)
	}

	// TODO: Add graceful shutdown
	apigateway.NewReverseProxy(config).ListenAndServe()
}
