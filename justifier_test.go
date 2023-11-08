package jwt2headers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Farrukhraz/jwt2headers"
)

func TestBaseLogic(t *testing.T) {
	jwtToken := "JWT_TOKEN_SHOULD_BE_HERO"
	cfg := jwt2headers.CreateConfig()
	cfg.RedirectUrl = "123"
	cfg.ContourSeparator = []jwt2headers.SeparatorStruct{
		{
			Domain:       "prod.fake.com",
			AllowedGroup: "PROD",
		},
		{
			Domain:       "dev.fake.com",
			AllowedGroup: "DEV",
		},
		{
			Domain:       "test.fake.com",
			AllowedGroup: "TEST",
		},
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := jwt2headers.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://localhost",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	autheliaCookie := http.Cookie{
		Name:  "authelia_session",
		Value: "Hello world!",
	}
	jwtCookie := http.Cookie{
		Name:  "jwt_token",
		Value: jwtToken,
	}
	req.AddCookie(&autheliaCookie)
	req.AddCookie(&jwtCookie)
	req.Header.Set("X-Forwarded-Host", "test.fake.com")

	handler.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Errorf("200 response was expected, but %v received", recorder.Code)
	}

	assertHeader(t, req, "X-User-Username", "manager")
	assertHeader(t, req, "X-User-Email", "manager@gmail.com")
	assertHeader(t, req, "X-User-Name", "Просто Менеджер")
}

func TestUserGroupNoAccess(t *testing.T) {
	jwtToken := "JWT_TOKEN_SHOULD_BE_HERO"
	cfg := jwt2headers.CreateConfig()
	cfg.RedirectUrl = "123"
	cfg.ContourSeparator = []jwt2headers.SeparatorStruct{
		{
			Domain:       "prod.fake.com",
			AllowedGroup: "PROD",
		},
		{
			Domain:       "dev.fake.com",
			AllowedGroup: "DEV",
		},
		{
			Domain:       "test.fake.com",
			AllowedGroup: "TEST",
		},
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := jwt2headers.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://localhost",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	autheliaCookie := http.Cookie{
		Name:  "authelia_session",
		Value: "Hello world!",
	}
	jwtCookie := http.Cookie{
		Name:  "jwt_token",
		Value: jwtToken,
	}
	req.AddCookie(&autheliaCookie)
	req.AddCookie(&jwtCookie)
	req.Header.Set("X-Forwarded-Host", "dev.fake.com")

	handler.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Errorf("403 response was expected, but %v received", recorder.Code)
	}
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	foundHeader := req.Header.Get(key)
	if foundHeader != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}
