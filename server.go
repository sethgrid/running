package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/sha256"

	"github.com/facebookgo/flagenv"
	"github.com/gorilla/mux"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// From ENV or flag
// idomatic go: no all caps. I know. I ignore.
var MYSQL_DB string
var MYSQL_USER string
var MYSQL_PW string

var STRAVA_CLIENT_SECRET string
var STRAVA_CLIENT_ID string
var STRAVA_ACCESS_TOKEN string

var COOKIE_EXPIRY time.Duration
var HMAC_KEY string

const (
	AuthCookieName = "auth_cookie"
)

// StravaOAuthTokenResponse is the data we get back after validating a user.
// Additionally, this is the data stored to the `AuthCookieName` cookie for frontend use.
type StravaOAuthTokenResponse struct {
	AccessToken   string  `json:"access_token"`
	StravaAthlete Athlete `json:"athlete"`
}

// Athlete represents athlete data from strava
type Athlete struct {
	ID                    int     `json:"id"`
	ResourceState         int     `json:"id"`
	FirstName             string  `json:"firstname"`
	LastName              string  `json:"lastname"`
	ProfileMedium         string  `json:"profile_medium"`
	Profile               string  `json:"profile"`
	City                  string  `json:"city"`
	State                 string  `json:"state"`
	Country               string  `json:"country"`
	Sex                   string  `json:"sex"`
	Friend                string  `json:"friend"`
	Follower              string  `json:"follower"`
	Premium               bool    `json:"premium"`
	CreateAt              string  `json:"created_at"`
	UpdatedAt             string  `json:"updated_at"`
	FollowerCount         int     `json:"follower_count"`
	FriendCount           int     `json:"friend_count"`
	MutualFriendCount     int     `json:"mutual_friend_count"`
	AthleteType           int     `json:"athete_type"`
	DatePreference        string  `json:"date_preference"`
	MeasurementPreference string  `json:"measurement_preference"`
	Email                 string  `json:"email"`
	FTP                   int     `json:"ftp"`
	Weight                float64 `json:"weight"`
	// ignoring clubs, bikes, and shoes
}

func main() {
	var port int
	flag.IntVar(&port, "port", 9000, "port upon which to run")
	flag.StringVar(&MYSQL_DB, "mysql-db", "db_name", "the mysql database name")
	flag.StringVar(&MYSQL_USER, "mysql-user", "db_user", "the mysql database user")
	flag.StringVar(&MYSQL_PW, "mysql-pw", "db_pw", "the mysql database pw")
	flag.StringVar(&STRAVA_ACCESS_TOKEN, "strava-access-token", "", "strava provided access token")
	flag.StringVar(&STRAVA_CLIENT_ID, "strava-client-id", "", "strava provided client id")
	flag.StringVar(&STRAVA_CLIENT_SECRET, "strava-client-secret", "", "strava provided client secret")
	flag.StringVar(&HMAC_KEY, "hmac-key", "abc123", "random string used for hmac sum")
	flag.DurationVar(&COOKIE_EXPIRY, "cookie-expiry", time.Hour*168, "set the expiry time on cookies. ex: 5h30m")

	flagenv.Parse()
	warningMissingConfigs()

	log.Printf("starting on :%d", port)

	r := mux.NewRouter()

	r.Handle("/", mwLogRequest(http.HandlerFunc(homeHandler)))
	r.Handle("/token_exchange", mwLogRequest(http.HandlerFunc(tokenHandler)))
	r.Handle("/app", mwLogRequest(http.HandlerFunc(appHandler)))

	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), r); err != nil {
		log.Println("unexpected error - %v", err)
	}
}

// homeHandler presents the index.html template
func homeHandler(w http.ResponseWriter, r *http.Request) {
	file, err := ioutil.ReadFile("index.html")
	if err != nil {
		log.Println("index.html not found")
		http.NotFoundHandler()
		return
	}
	t, err := template.New("index").Parse(string(file))
	if err != nil {
		log.Println("unable to parse index.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing templates")
	}
	data := struct {
		StravaClientID string
	}{
		StravaClientID: STRAVA_CLIENT_ID,
	}

	err = t.Execute(w, data)
	if err != nil {
		log.Printf("error executing template in homeHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing templates")
	}
}

// tokenHandler is the strava oauth callback domain handler.
// It validates the request, requests oAuth details, and then commits the data to the `AuthCookieName` cookie.
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	// ****************
	// get query params

	if r.URL.Query().Get("error") == "access_denied" {
		errHandler(w, r, http.StatusForbidden, "strava has denied access")
		return
	}

	state := r.URL.Query().Get("state")
	if state == "" {
		errHandler(w, r, http.StatusBadRequest, "missing state parameter got "+state)
		return
	}
	_ = state // state is, as of yet, unused

	code := r.URL.Query().Get("code")
	if code == "" {
		errHandler(w, r, http.StatusBadRequest, "missing code parameter")
		return
	}

	// ***************
	// oauth handshake

	requestData := struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Code         string `json:"code"`
	}{
		STRAVA_CLIENT_ID, STRAVA_CLIENT_SECRET, code,
	}
	b, err := json.Marshal(requestData)
	if err != nil {
		log.Printf("error marshalling requestData - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "unable to prepare data for oauth token request")
		return
	}

	resp, err := http.Post("https://www.strava.com/oauth/token", "application/json", bytes.NewReader(b))
	if err != nil {
		log.Println("error posting to strava oauth token endpoint - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "error communicating with strava")
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		errHandler(w, r, http.StatusInternalServerError, "unable to read strava response")
		return
	}

	if resp.StatusCode > 300 {
		log.Printf("unexpected result from strava getting token: [%d] %s", resp.StatusCode, string(body))
		errHandler(w, r, http.StatusInternalServerError, "unexpected result from strava")
		return
	}

	var OAuthData StravaOAuthTokenResponse
	err = json.Unmarshal(body, &OAuthData)
	if err != nil {
		log.Printf("unable to unmarshal oauth data - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "unexpected result structure from strava")
		return
	}

	// ****************************
	// set AuthCookieName and redirect
	mac := hmac.New(sha256.New, []byte(HMAC_KEY))
	_, err = mac.Write(body)
	if err != nil {
		log.Printf("unable to encode data for auth cookie - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "error encoding auth cookie")
		return
	}

	cookie := http.Cookie{}
	cookie.Name = AuthCookieName
	cookie.Value = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s%s%s", string(body), "::hmac::", string(mac.Sum(nil)))))
	cookie.Expires = time.Now().Add(time.Hour * time.Duration(COOKIE_EXPIRY))

	http.SetCookie(w, &cookie)

	log.Println("forwarding request to /app")
	w.Header().Set("Location", "/app")
	w.WriteHeader(301)
	w.Write([]byte("Redirecting to /app..."))
}

func appHandler(w http.ResponseWriter, r *http.Request) {
	// ***********************
	// grab cookie and validate hmac signatures to ensure no tampering happened

	cookie, err := r.Cookie(AuthCookieName)
	if err != nil {
		log.Printf("error obtaining auth cookie - %v", err)
		authErrHandler(w, r, "Unable to read cookie data. Please sign back in.")
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		log.Printf("error decoding cookie value - %v", decoded)
		authErrHandler(w, r, "Unable to decode cookie data. Please sign back in.")
	}
	parts := strings.Split(string(decoded), "::hmac::")
	if len(parts) != 2 {
		log.Printf("missing parts on cookie: %s", cookie)
		authErrHandler(w, r, "Corrupt cookie data. Please sign back in.")
		return
	}
	marshalled, wantMac := parts[0], parts[1]
	gotMac := hmac.New(sha256.New, []byte(HMAC_KEY))
	_, _ = gotMac.Write([]byte(marshalled))
	if !hmac.Equal(gotMac.Sum(nil), []byte(wantMac)) {
		log.Printf("macs do not match")
		authErrHandler(w, r, "Invalid cookie data. Please sign back in.")
		return
	}

	var cookieData StravaOAuthTokenResponse
	err = json.Unmarshal([]byte(marshalled), &cookieData)
	if err != nil {
		log.Printf("error marshalling cookie data - %v", err)
		authErrHandler(w, r, "unable to decode coodie data. Please sign back in.")
		return
	}

	// ***********************
	// load template

	file, err := ioutil.ReadFile("app.html")
	if err != nil {
		log.Println("app.html not found")
		http.NotFoundHandler()
		return
	}
	t, err := template.New("app").Parse(string(file))
	if err != nil {
		log.Println("unable to parse app.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing app template")
	}
	data := struct {
		Email string
	}{
		Email: cookieData.StravaAthlete.Email,
	}

	err = t.Execute(w, data)
	if err != nil {
		log.Printf("error executing template in appHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing app template")
	}
}

// authErrHandler redirects a request to `/` and puts a message in the query for use at the index
func authErrHandler(w http.ResponseWriter, r *http.Request, msg string) {
	log.Println("forwarding un-authed request to index")
	w.Header().Set("Location", "/?message="+url.QueryEscape(msg))
	w.WriteHeader(301)
	w.Write([]byte("Redirecting to index..."))
}

// errHanlder logs and writes a message and sets a status code
func errHandler(w http.ResponseWriter, r *http.Request, statusCode int, msg string) {
	log.Printf("%s - [%d] %s", r.URL, statusCode, msg)
	w.WriteHeader(statusCode)
	w.Write([]byte(msg))
}

// mwLogRequest is a middleware that times each request and logs it
func mwLogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now().UnixNano()
		reqID := fmt.Sprintf("%#05d", rand.Intn(100000)+1)
		log.Printf("[%s] %s", reqID, r.URL.String())
		next.ServeHTTP(w, r)
		log.Printf("[%s] complete %d ms", reqID, (time.Now().UnixNano()-start)/1e6)
	})
}

// warningMissingConfigs provides start up errors for inappropriate config values
func warningMissingConfigs() {
	if STRAVA_ACCESS_TOKEN == "" {
		log.Println("Warning: strava-access-token empty. See -h.")
	}
	if STRAVA_CLIENT_ID == "" {
		log.Println("Warning: strava-client-id empty. See -h.")
	}
	if STRAVA_CLIENT_SECRET == "" {
		log.Println("Warning: strava-client-secret empty. See -h.")
	}
	if MYSQL_DB == "" {
		log.Println("Warning: mysql-db empty. See -h.")
	}
	if MYSQL_USER == "" {
		log.Println("Warning: mysql-user empty. See -h.")
	}
	if MYSQL_USER == "root" {
		log.Println("Warning: using root as mysql-user.")
	}
}
