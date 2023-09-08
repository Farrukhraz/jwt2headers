package jwt2headers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Farrukhraz/jwt2headers"
)

func TestDemo(t *testing.T) {
	cfg := jwt2headers.CreateConfig()
	cfg.Cookies["session"] = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImE4YzFhNyIsInR5cCI6IkpXVCJ9.eyJhbXIiOlsicHdkIl0sImF0X2hhc2giOiJMdmcxcFBFSVpvWFl5ZDl0TnpZd2JBIiwiYXVkIjpbInB5dGhvbl9jbGllbnQiXSwiYXV0aF90aW1lIjoxNjk0MTIwMTU5LCJhenAiOiJweXRob25fY2xpZW50IiwiY2xpZW50X2lkIjoicHl0aG9uX2NsaWVudCIsImVtYWlsIjoieW91QGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV4cCI6MTY5NDEyMTk2MiwiZ3JvdXBzIjpbImFkbWlucyIsImRldiJdLCJpYXQiOjE2OTQxMjAxNjIsImlzcyI6Imh0dHBzOi8vYXV0aC5iZXN0cHJveGlmaWVyLnJ1IiwianRpIjoiZDA4M2ZiM2ItYmQwOS00NTM1LWFmNmYtMWJlNGFhYzFiOGM0IiwibmFtZSI6IllvdXIgTmFtZSIsIm5vbmNlIjoiN0RORklJM044OEFEN1FTMVVCRjgiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ1c2VybmFtZSIsInJhdCI6MTY5NDEyMDE2MCwic3ViIjoiN2VlMTI3YmYtNmIzZS00Zjc0LWE1NmEtZjQyYWUwZTNjNzdkIn0.dBHzFRscepuGMMYXAjFkeobJQhQm4KaYM4madk7BQL3MreH8u5bYs0hedHCkC9hGw_Y9O1FW5nnaYnwvGIloSIvg3CHbkRuWbQH-7Jbc0wuAOAGYid_Or_I8WDawiezvPyZjU4De18lknFBTNBP74ThMk1wwvY2iyZFqE6uEx49cQdQBHlH68-hbvp1GZyvJRCdJcgGsND7Zza6y6srI39YObLA6o0uKpDRAILImGxJPp1XaCEPbcO4JJ42jFpgY0C1NfghAZzggQrEWdKhYeA1TcgiOyiMHw8DEUZEjYFaObODXBla-qijkffq37alFjx2_oRgXtlZTkn9Y937ZL3w8EX_k7TMhJhh7G5TNdzpOOpUeB4EJWNDWA_KbTYkv5hT6tB1JahY1238q2HQERBhbccWXLfC7jjIvX-Og6HpgYHk_uFIHVw0k6zgq242K_17JaAuWOVZRJL4dqWMcYyz-zPrHJGkc7IQvi-h7gvm7vXgHc65DqZ12UNJmTuEyudrH7nUtBhz-q-WqI5L-LM2nRjczL9yYvEcpqCPhouK6SzxWLSg70_kQESZAqyurTuh1BifNhnqjDf9RYl1I57lxO_4dKMfVKDMoYSVZueARsaR2sejX4gVehfhNpr34mujtl3FPWeyJpAHCaR6NqoftCx5RkXRelk4U8pXWetA"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := jwt2headers.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "X-User-Username", "username")
	assertHeader(t, req, "X-User-Email", "you@example.com")
	assertHeader(t, req, "X-User-Name", "Your Name")
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}
