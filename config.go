package apigateway

import (
	"github.com/spf13/viper"
)

type Config struct {
	Auth       Auth
	Gateway    Gateway
	MatchPaths []MatchPaths
}

type Auth struct {
	Internal       AuthInternal
	BasePath       string
	SigninPath     string
	SignoutPath    string
	SignupPath     string
	ValidationPath string
}

type AuthInternal struct {
	IDHeader string
}

type Gateway struct {
	Schema      string
	TLSCertFile string
	TLSKeyFile  string
	Port        uint16
}

type MatchPaths struct {
	Value      string
	TargetHost string
	TargetPort uint16
}

func PrepareConfigFile(name string, searchPaths []string) {
	viper.SetConfigName(name)
	viper.SetConfigType("yaml")
	for _, path := range searchPaths {
		viper.AddConfigPath(path)
	}
}

func NewConfig() (Config, error) {
	var conf Config

	if err := viper.ReadInConfig(); err != nil {
		return conf, err
	}

	err := viper.Unmarshal(&conf)
	if err != nil {
		return conf, err
	}

	// TODO: Do validations for URL paths and similar...

	return conf, nil
}
