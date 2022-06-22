package apigateway

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func NewReverseProxy(conf Config) *reverseProxy {
	var prx reverseProxy
	prx.config = conf

	if conf.Gateway.Schema == "https" {
		tlsPair, err := tls.LoadX509KeyPair(
			conf.Gateway.TLSCertFile,
			conf.Gateway.TLSKeyFile,
		)
		if err != nil {
			log.Fatalf("err = NewReverseProxy = LoadX509KeyPair = %v", err)
		}

		prx.tlsCerts = append(prx.tlsCerts, tlsPair)
	}
	return &prx
}

type reverseProxy struct {
	config   Config
	tlsCerts []tls.Certificate
}

func (prx *reverseProxy) ListenAndServe() {
	g := gin.Default()

	g.POST("/auth/:intent", prx.authHandler)
	g.Any("/api/*path", prx.genericHandler)

	errChan := make(chan error, 1)
	go prx.Run(g, errChan)

	if err := <-errChan; err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func (prx *reverseProxy) Run(g *gin.Engine, ch chan error) {
	if prx.config.Gateway.Schema == "https" {
		ch <- g.RunTLS(
			fmt.Sprintf("0.0.0.0:%d", prx.config.Gateway.Port),
			prx.config.Gateway.TLSCertFile,
			prx.config.Gateway.TLSKeyFile,
		)
		return
	}
	ch <- g.Run(fmt.Sprintf("0.0.0.0:%d", prx.config.Gateway.Port))
}

// TODO: Evaluate OAuth2 integration
func (prx *reverseProxy) authHandler(c *gin.Context) {
	var (
		u   *url.URL
		err error
	)
	intent := strings.ToLower(c.Param("intent"))

	switch intent {
	case "signup":
		u, err = prx.parseURL(
			prx.config.Gateway.Schema,
			prx.config.Auth.BasePath,
			prx.config.Auth.SignupPath,
		)

	case "signin":
		u, err = prx.parseURL(
			prx.config.Gateway.Schema,
			prx.config.Auth.BasePath,
			prx.config.Auth.SigninPath,
		)

	case "signout":
		u, err = prx.parseURL(
			prx.config.Gateway.Schema,
			prx.config.Auth.BasePath,
			prx.config.Auth.SignoutPath,
		)

	default:
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
	}
	prx.newProxy(u).ServeHTTP(c.Writer, c.Request)
}

func (prx *reverseProxy) genericHandler(c *gin.Context) {
	path := "/" + strings.Trim(c.Param("path"), "/")

	split := strings.Split(path, "/")
	if len(split) <= 1 {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	for _, matchPath := range prx.config.MatchPaths {
		// TODO: Test alternative path matching methods other than .HasPrefix()
		if strings.HasPrefix(path, matchPath.Value) {
			// Validate authorization
			au, err := prx.parseURL(
				prx.config.Gateway.Schema,
				prx.config.Auth.BasePath,
				prx.config.Auth.ValidationPath,
			)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			req, err := http.NewRequest("POST", au.String(), c.Copy().Request.Body)
			if err != nil {
				log.Println(err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			req.Header.Add("Content-Type", "application/json")

			// Pass Authorization header
			req.Header.Add("Authorization", c.GetHeader("Authorization"))

			// Pass cookies
			cookies := c.Copy().Request.Cookies()
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}

			// Determine whether the request is for websocket upgrade,
			// [https://datatracker.ietf.org/doc/html/rfc6455] [Page 19] [2.]
			if c.GetHeader("Upgrade") == "websocket" {
				// Additionally, pass query string if it's a websocket connection
				// Assumes that required authorization secrets are sent via query (e.g., wss://.../?token=...)
				// TODO: Review unusual auth. handling methods such as passing secrets using "Sec-WebSocket-Protocol" header
				q := req.URL.Query()
				for k, v := range c.Request.URL.Query() {
					for _, subv := range v {
						q.Add(k, subv)
					}
				}
				req.URL.RawQuery = q.Encode()
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Println(err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()

			if code := resp.StatusCode; code != 200 {
				c.DataFromReader(code, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, map[string]string{})
				return
			}

			// TODO: Get expected authorization response fields from config. file
			var abody struct {
				Id string
				// Email string
			}
			// TODO: Support response bodies other than JSON
			if err = json.NewDecoder(resp.Body).Decode(&abody); err != nil {
				log.Println(err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			// Forward to internal service
			u, err := prx.parseURL(prx.config.Gateway.Schema, fmt.Sprintf("%s:%d%s", matchPath.TargetHost, matchPath.TargetPort, path))
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			prx.newServiceProxy(u, abody.Id).ServeHTTP(c.Writer, c.Request)
			return
		}
	}
	c.AbortWithStatus(http.StatusNotFound)
}

func (prx *reverseProxy) parseURL(schema string, addr ...string) (*url.URL, error) {
	u, err := url.Parse(fmt.Sprintf("%s://%s", schema, strings.Join(addr, "")))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return u, nil
}

func (prx *reverseProxy) newProxyTransport() *http.Transport {
	if prx.config.Gateway.Schema == "https" {
		return &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: prx.tlsCerts,
			},
		}
	}
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

func (prx *reverseProxy) newProxy(url *url.URL) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(url)
	rp.Director = func(req *http.Request) {
		req.Host = url.Host
		req.URL.Scheme = url.Scheme
		req.URL.Host = url.Host
		req.URL.Path = url.Path
	}
	rp.Transport = prx.newProxyTransport()
	return rp
}

func (prx *reverseProxy) newServiceProxy(url *url.URL, id string) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(url)
	rp.Director = func(req *http.Request) {
		req.Host = url.Host
		req.URL.Scheme = url.Scheme
		req.URL.Host = url.Host
		req.URL.Path = url.Path

		req.Header.Set(prx.config.Auth.Internal.IDHeader, id)
	}
	rp.ModifyResponse = func(req *http.Response) error {
		req.Header.Del(prx.config.Auth.Internal.IDHeader)
		return nil
	}
	rp.Transport = prx.newProxyTransport()
	return rp
}
