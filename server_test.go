package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAppHandlerSuccess(t *testing.T) {
	t.Log("given a valid cookie, html and a 200 response should return")

	req, err := http.NewRequest("GET", "http://somedomain/app", nil)
	if err != nil {
		log.Fatal(err)
	}

	req.AddCookie(genTestAuthCookie())

	w := httptest.NewRecorder()
	appHandler(w, req)

	t.Logf("appHandler:\ncode:%d\nheaders:%+v\nbody:%s", w.Code, w.HeaderMap, w.Body.String())

	if !strings.Contains(w.Body.String(), "<html") {
		t.Error("no html tag found in response body")
	}

	if got, want := w.Code, http.StatusOK; got != want {
		t.Errorf("got status code %d, want %d", got, want)
	}
}

func TestAppHandlerMissingCookieErr(t *testing.T) {
	t.Log("given a missing cookie, no html and a 401 response should return")
	log.SetOutput(ioutil.Discard)

	req, err := http.NewRequest("GET", "http://somedomain/app", nil)
	if err != nil {
		log.Fatal(err)
	}

	// don't add the auth cookie
	//req.AddCookie(genTestAuthCookie())

	w := httptest.NewRecorder()
	appHandler(w, req)

	t.Logf("appHandler:\ncode:%d\nheaders:%+v\nbody:%s", w.Code, w.HeaderMap, w.Body.String())

	if strings.Contains(w.Body.String(), "<html>") {
		t.Error("no html should be found in response body")
	}

	if got, want := w.Code, http.StatusUnauthorized; got != want {
		t.Errorf("got status code %d, want %d", got, want)
	}
}

func TestAppHandlerAlteredCookieErr(t *testing.T) {
	t.Log("given a altered cookie, no html and a 401 response should return")
	log.SetOutput(ioutil.Discard)

	req, err := http.NewRequest("GET", "http://somedomain/app", nil)
	if err != nil {
		log.Fatal(err)
	}

	cookie := genTestAuthCookie()
	cookie.Value = "altered" + cookie.Value
	req.AddCookie(cookie)

	w := httptest.NewRecorder()
	appHandler(w, req)

	t.Logf("appHandler:\ncode:%d\nheaders:%+v\nbody:%s", w.Code, w.HeaderMap, w.Body.String())

	if strings.Contains(w.Body.String(), "<html>") {
		t.Error("no html should be found in response body")
	}

	if got, want := w.Code, http.StatusUnauthorized; got != want {
		t.Errorf("got status code %d, want %d", got, want)
	}
}

func genTestAuthCookie() *http.Cookie {
	oAuthToken := StravaOAuthTokenResponse{}
	oAuthToken.AccessToken = "test-bearer-token"
	oAuthToken.StravaAthlete.Email = "athlete@example.com"
	oAuthToken.StravaAthlete.ID = 1001

	rawBody, err := json.Marshal(oAuthToken)
	if err != nil {
		log.Fatalf("unable to marshal token body for testing - %v", err)
	}

	mac := hmac.New(sha256.New, []byte(HMAC_KEY))
	_, err = mac.Write(rawBody)
	if err != nil {
		log.Fatalf("unable to write hmac - %v", err)
	}

	cookie := &http.Cookie{}
	cookie.Name = AuthCookieName
	cookie.Value = padBase64(base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s%s%s", string(rawBody), "::hmac::", base64.StdEncoding.EncodeToString((mac.Sum(nil)))))))
	cookie.Expires = time.Now().Add(COOKIE_EXPIRY)

	return cookie
}

// fakeHTTPServer is a stub http.Handler for testing middleware.
// Not sure why I had to implement this; feel like I missed something in httptest.
type fakeHTTPServer struct{}

func (f fakeHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

func TestMiddleWareAuthSuccess(t *testing.T) {
	t.Log("given a valid cookie, the next handler should be called")
	log.SetOutput(ioutil.Discard)

	w := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "http://somedomain/app", nil)
	if err != nil {
		log.Fatal(err)
	}

	req.AddCookie(genTestAuthCookie())

	nextHandler := fakeHTTPServer{}

	mwAuthenticated(nextHandler).ServeHTTP(w, req)

	t.Logf("appHandler:\ncode:%d\nheaders:%+v\nbody:%s", w.Code, w.HeaderMap, w.Body.String())

	if got, want := w.Code, http.StatusOK; got != want {
		t.Errorf("got response code %d, want %d", got, want)
	}
}

func TestMiddleWareAuthMissingCookie(t *testing.T) {
	t.Log("given a missing cookie, a 401 should be returned")
	log.SetOutput(ioutil.Discard)

	w := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "http://somedomain/app", nil)
	if err != nil {
		log.Fatal(err)
	}

	// dont' include cookie
	//req.AddCookie(genTestAuthCookie())

	nextHandler := fakeHTTPServer{}

	mwAuthenticated(nextHandler).ServeHTTP(w, req)

	t.Logf("appHandler:\ncode:%d\nheaders:%+v\nbody:%s", w.Code, w.HeaderMap, w.Body.String())

	if got, want := w.Code, http.StatusUnauthorized; got != want {
		t.Errorf("got response code %d, want %d", got, want)
	}
}

func TestMiddleWareAuthAlteredCookie(t *testing.T) {
	t.Log("given an altered cookie, a 401 should be returned")
	log.SetOutput(ioutil.Discard)

	w := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "http://somedomain/app", nil)
	if err != nil {
		log.Fatal(err)
	}

	cookie := genTestAuthCookie()
	cookie.Value = "altered-" + cookie.Value
	req.AddCookie(cookie)

	nextHandler := fakeHTTPServer{}

	mwAuthenticated(nextHandler).ServeHTTP(w, req)

	t.Logf("appHandler:\ncode:%d\nheaders:%+v\nbody:%s", w.Code, w.HeaderMap, w.Body.String())

	if got, want := w.Code, http.StatusUnauthorized; got != want {
		t.Errorf("got response code %d, want %d", got, want)
	}
}

func TestComma(t *testing.T) {
	var testCases = []struct {
		N int64
		S string
	}{
		{N: 1, S: "1"},
		{N: 10, S: "10"},
		{N: 100, S: "100"},
		{N: 1000, S: "1,000"},
		{N: 10000, S: "10,000"},
		{N: 100000, S: "100,000"},
		{N: 1000000, S: "1,000,000"},
		{N: 10000000, S: "10,000,000"},
		{N: 100000000, S: "100,000,000"},
		{N: 1000000000, S: "1,000,000,000"},
		{N: 9223372036854775807, S: "9,223,372,036,854,775,807"},
	}

	for _, tc := range testCases {
		if got, want := Comma(tc.N), tc.S; got != want {
			t.Errorf("got %q, want %q for %d", got, want, tc.N)
		}
	}
}
