// Package plugindemo a demo plugin.
package jwt2headers

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"text/template"
)

type Claims struct {
	Value string `json:"jwt_token"`
}

type UserInfoStruct struct {
	Username string
	RealName string
	Email    string
	//Groups   []string
}

// Config the plugin configuration.
type Config struct {
	Cookies map[string]string `json:"cookies,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Cookies: make(map[string]string),
	}
}

// Demo a Demo plugin.
type Demo struct {
	next     http.Handler
	cookies  map[string]string
	name     string
	template *template.Template
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Cookies) == 0 {
		return nil, fmt.Errorf("cookies cannot be empty")
	}

	return &Demo{
		cookies:  config.Cookies,
		next:     next,
		name:     name,
		template: template.New("demo").Delims("[[", "]]"),
	}, nil
}

func (a *Demo) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("jwt_token")
	if err != nil {
		http.Error(rw, "Required cookie is not found", http.StatusUnauthorized)
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			errorMessage := fmt.Sprintf("Unexpected signing method: %v", token.Header["alg"])
			http.Error(rw, errorMessage, http.StatusInternalServerError)
		}
		return token, nil
	})

	// ToDo check that cookie is not expired
	// ToDo check that cookie signature is valid

	var userIfno UserInfoStruct
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		userIfno.Username = fmt.Sprintf("%+v", claims["preferred_username"])
		userIfno.RealName = fmt.Sprintf("%+v", claims["name"])
		userIfno.Email = fmt.Sprintf("%+v", claims["email"])
		// ToDo get user's groups and set them in headers
	}

	req.Header.Set("X-User-Username", userIfno.Username)
	req.Header.Set("X-User-Email", userIfno.Email)
	req.Header.Set("X-User-Name", userIfno.RealName)

	a.next.ServeHTTP(rw, req)
}
