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

func TestAppHandler(t *testing.T) {
	t.Log("given a valid cookie, html and a 200 response should return")

	req, err := http.NewRequest("GET", "http://somedomain/app", nil)
	if err != nil {
		log.Fatal(err)
	}

	req.AddCookie(genTestAuthCookie())

	w := httptest.NewRecorder()
	appHandler(w, req)

	t.Logf("appHandler:\ncode:%d\nheaders:%+v\nbody:%s", w.Code, w.HeaderMap, w.Body.String())

	if !strings.Contains(w.Body.String(), "<html>") {
		t.Error("no html tag found in response body")
	}

	if got, want := w.Code, http.StatusOK; got != want {
		t.Errorf("got status code %d, want %d", got, want)
	}
}

func TestAppHandlerMissingCookieErr(t *testing.T) {
	t.Log("given a missing cookie, no html and a 301 response should return")
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

	if got, want := w.Code, http.StatusMovedPermanently; got != want {
		t.Errorf("got status code %d, want %d", got, want)
	}
}

func TestAppHandlerAlteredCookieErr(t *testing.T) {
	t.Log("given a altered cookie, no html and a 301 response should return")
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

	if got, want := w.Code, http.StatusMovedPermanently; got != want {
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
	cookie.Value = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s%s%s", string(rawBody), "::hmac::", string(mac.Sum(nil)))))
	cookie.Expires = time.Now().Add(COOKIE_EXPIRY)

	return cookie
}

// fakeHTTPServer is a stub http.Handler for testing middleware.
// Not sure why I had to implement this; feel like I missed something in httptest.
type fakeHTTPServer struct{}

func (f fakeHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

func TestMiddleWareAuth(t *testing.T) {
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
	t.Log("given a valid cookie, the next handler should be called")
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

	if got, want := w.Code, http.StatusMovedPermanently; got != want {
		t.Errorf("got response code %d, want %d", got, want)
	}
}

func TestMiddleWareAuthAlteredCookie(t *testing.T) {
	t.Log("given a valid cookie, the next handler should be called")
	log.SetOutput(ioutil.Discard)

	w := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "http://somedomain/app", nil)
	if err != nil {
		log.Fatal(err)
	}

	cookie := genTestAuthCookie()
	cookie.Value = "altered" + cookie.Value
	req.AddCookie(cookie)

	nextHandler := fakeHTTPServer{}

	mwAuthenticated(nextHandler).ServeHTTP(w, req)

	t.Logf("appHandler:\ncode:%d\nheaders:%+v\nbody:%s", w.Code, w.HeaderMap, w.Body.String())

	if got, want := w.Code, http.StatusMovedPermanently; got != want {
		t.Errorf("got response code %d, want %d", got, want)
	}
}
