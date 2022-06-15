package main

import (
	"github.com/baturalpk/apigateway"
	"log"
)

func main() {
	apigateway.PrepareConfigFile("config", []string{"./examples"})
	config, err := apigateway.NewConfig()
	if err != nil {
		log.Fatalln(err)
	}

	authProvider, err := apigateway.NewAuthProvider(config)
	if err != nil {
		log.Fatalln(err)
	}

	apigateway.NewReverseProxy(config, authProvider).ListenAndServe()
}
