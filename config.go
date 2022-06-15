package apigateway

import (
	"github.com/spf13/viper"
	"log"
)

type Config struct {
	Authentication Authentication
	Authorization  Authorization
	Gateway        Gateway
	MatchPaths     []MatchPaths
}

type Authentication struct {
	IdentityStore identityStore
}

type identityStore struct {
	DBName, Host, Password, User string
	Port                         uint16
}

type Authorization struct {
	HmacSecret string
}

type Gateway struct {
	Port uint16
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
		log.Println(path)
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

	return conf, nil
}
