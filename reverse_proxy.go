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
	return &reverseProxy{config: conf}
}

type reverseProxy struct {
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
	var (
		u   *url.URL
		err error
	)
	intent := strings.ToLower(c.Param("intent"))

	switch intent {
	case "signup":
		u, err = prx.parseURL(
			prx.config.Auth.BasePath,
			prx.config.Auth.SignupPath,
		)

	case "signin":
		u, err = prx.parseURL(
			prx.config.Auth.BasePath,
			prx.config.Auth.SigninPath,
		)

	case "signout":
		u, err = prx.parseURL(
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
		if strings.HasPrefix(path, matchPath.Value) {
			// Validate authorization
			au, err := prx.parseURL(
				prx.config.Auth.BasePath,
				prx.config.Auth.ValidationPath,
			)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			req, err := http.NewRequest("POST", au.String(), c.Copy().Request.Body)
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Authorization", c.GetHeader("Authorization"))
			cookies := c.Copy().Request.Cookies()
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}
			if err != nil {
				log.Println(err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
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
			u, err := prx.parseURL(fmt.Sprintf("%s:%d%s", matchPath.TargetHost, matchPath.TargetPort, path))
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

// TODO: Configure and test HTTPS situations
func (prx *reverseProxy) parseURL(addr ...string) (*url.URL, error) {
	u, err := url.Parse(fmt.Sprintf("http://%s", strings.Join(addr, "")))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return u, nil
}

func (*reverseProxy) newProxy(url *url.URL) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(url)
	rp.Director = func(req *http.Request) {
		req.Host = url.Host
		req.URL.Scheme = url.Scheme
		req.URL.Host = url.Host
		req.URL.Path = url.Path
	}
	rp.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
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
	rp.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return rp
}
