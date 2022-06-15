package apigateway

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func NewReverseProxy(conf Config, ap *authProvider) *reverseProxy {
	return &reverseProxy{
		authp:  ap,
		config: conf,
	}
}

type reverseProxy struct {
	authp  *authProvider
	config Config
}

func (prx *reverseProxy) ListenAndServe() {
	g := gin.Default()

	g.POST("/auth/:intent", prx.authHandler)
	g.Any("/api/*path", prx.genericHandler)

	err := g.Run(fmt.Sprintf("0.0.0.0:%d", prx.config.Gateway.Port))
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func (prx *reverseProxy) authHandler(c *gin.Context) {
	intent := c.Param("intent")
	switch intent {
	case "signup":
		var body NewIdentityRequest
		if err := c.Bind(&body); err != nil {
			return
		}
		if resp, err := prx.authp.NewIdentity(body); err != nil {
			if resp.existingEmailError {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	case "signin":
		var body AuthenticateRequest
		if err := c.Bind(&body); err != nil {
			return
		}
		resp, err := prx.authp.Authenticate(body)
		if err != nil {
			if resp.identityVerificationFailed {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.JSON(http.StatusOK, resp.tokenString)
	default:
		c.AbortWithStatus(http.StatusNotFound)
	}
	return
}

func (prx *reverseProxy) genericHandler(c *gin.Context) {
	path := "/" + strings.Trim(c.Param("path"), "/")

	split := strings.Split(path, "/")
	if len(split) <= 1 {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	for _, matchPath := range prx.config.MatchPaths {
		if strings.HasPrefix(path, matchPath.Value) {
			tokenString, err := extractBearer(strings.Trim(c.GetHeader("Authorization"), " "))
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			resp, err := prx.authp.ValidateAuthorization(tokenString)
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			u, err := prx.ParseURL(fmt.Sprintf("%s:%d", matchPath.TargetHost, matchPath.TargetPort))
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			prx.NewProxy(u, resp.id).ServeHTTP(c.Writer, c.Request)
			return
		}
	}

	c.AbortWithStatus(http.StatusNotFound)
	return
}

func (prx *reverseProxy) ParseURL(addr string) (*url.URL, error) {
	u, err := url.Parse(fmt.Sprintf("https://%s", addr))
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (*reverseProxy) NewProxy(url *url.URL, userID string) *httputil.ReverseProxy {
	prx := httputil.NewSingleHostReverseProxy(url)
	prx.Director = func(req *http.Request) {
		req.Host = url.Host
		req.URL.Scheme = url.Scheme
		req.URL.Host = url.Host
		req.URL.Path = url.Path

		// Registered microservices can safely recognize the user by accessing header["x-user-id"]
		req.Header.Set("x-user-id", userID)
	}
	prx.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return prx
}

const (
	BearerPrefix = "Bearer "
	BearerN      = len(BearerPrefix)
)

func extractBearer(header string) (string, error) {
	if len(header) < BearerN || header[:BearerN] != BearerPrefix {
		return "", errors.New("invalid bearer header")
	}
	return header[BearerN:], nil
}
