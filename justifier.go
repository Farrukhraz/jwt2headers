// Package plugindemo a demo plugin.
package jwt2headers

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

type Claims struct {
	Value string `json:"jwt_token"`
}

type UserInfoStruct struct {
	Username string
	RealName string
	Email    string
	Groups   []string
}

// Config the plugin configuration.
type Config struct {
	Cookies     map[string]string `json:"cookies,omitempty"`
	RedirectUrl string            `json:"redirectUrl"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Cookies: make(map[string]string),
	}
}

// Demo a Demo plugin.
type Demo struct {
	next        http.Handler
	cookies     map[string]string
	redirectUrl string
	name        string
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.RedirectUrl) == 0 {
		return nil, fmt.Errorf("'redirectUrl' parameter in configuration file cannot be empty")
	}

	return &Demo{
		cookies:     config.Cookies,
		redirectUrl: config.RedirectUrl,
		next:        next,
		name:        name,
	}, nil
}

func (a *Demo) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	_, err := req.Cookie("authelia_session")
	if err != nil {
		fmt.Println(rw, "Required authentication cookie is not found")
		http.Redirect(rw, req, a.redirectUrl, http.StatusSeeOther)
		a.next.ServeHTTP(rw, req)
	}

	cookie, err := req.Cookie("jwt_token")
	if err != nil {
		fmt.Println(rw, "Required authorization cookie is not found")
		http.Redirect(rw, req, a.redirectUrl, http.StatusSeeOther)
		a.next.ServeHTTP(rw, req)
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			errorMessage := fmt.Sprintf("Unexpected signing method: %v", token.Header["alg"])
			http.Error(rw, errorMessage, http.StatusInternalServerError)
			a.next.ServeHTTP(rw, req)
		}
		return token, nil
	})

	// ToDo check that cookie is not expired. If expired request fresh jwt_token and
	//  return it to frontend client with redirect request (to previously requested url)

	// ToDo check that cookie signature is valid

	var userIfno UserInfoStruct
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		userIfno.Username = fmt.Sprintf("%+v", claims["preferred_username"])
		userIfno.RealName = fmt.Sprintf("%+v", claims["name"])
		userIfno.Email = fmt.Sprintf("%+v", claims["email"])
		groupsInterface := claims["groups"].([]interface{})
		userIfno.Groups = make([]string, len(groupsInterface))
		for i, v := range groupsInterface {
			userIfno.Groups[i] = v.(string)
		}
	}

	req.Header.Set("X-User-Username", userIfno.Username)
	req.Header.Set("X-User-Email", userIfno.Email)
	req.Header.Set("X-User-Name", userIfno.RealName)
	req.Header.Set("X-User-Groups", strings.Join(userIfno.Groups[:], ";"))

	a.next.ServeHTTP(rw, req)
}
