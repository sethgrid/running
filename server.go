package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
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

	"github.com/facebookgo/flagenv"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/sethgrid/gencurl"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// From ENV or flag
// idomatic go: no all caps. I know. I ignore.
var MYSQL_DB string
var MYSQL_USER string
var MYSQL_PW string
var MYSQL_HOST string
var MYSQL_PORT string

var STRAVA_CLIENT_SECRET string
var STRAVA_CLIENT_ID string
var STRAVA_ACCESS_TOKEN string

var COOKIE_EXPIRY time.Duration
var EARLIEST_POLL_UNIX int64
var POLL_INTERVAL time.Duration
var HMAC_KEY string

// in-app set up
const (
	AuthCookieName  = "auth_cookie"
	MysqlDateFormat = "2006-01-02 15:04:05"
)

var DB *sql.DB

// StravaOAuthTokenResponse is the data we get back after validating a user.
// Additionally, this is the data stored to the `AuthCookieName` cookie for frontend use.
type StravaOAuthTokenResponse struct {
	AccessToken   string  `json:"access_token"`
	StravaAthlete Athlete `json:"athlete"`
}

// Athlete represents athlete data from strava
type Athlete struct {
	ID                    int     `json:"id"`
	ResourceState         int     `json:"resource_state"`
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

// Activity represents the interesting fields from the list activty endpoint
type Activity struct {
	ID        int     `json:"ID"`
	Distance  float32 `json:"distance"`
	Type      string  `json:"type"`
	StartDate string  `json:"start_date"` // 2013-08-24T00:04:12Z
}

func main() {
	var port int
	flag.IntVar(&port, "port", 9000, "port upon which to run")
	flag.StringVar(&MYSQL_DB, "mysql-db", "db_name", "the mysql database name")
	flag.StringVar(&MYSQL_USER, "mysql-user", "root", "the mysql database user")
	flag.StringVar(&MYSQL_PW, "mysql-pw", "", "the mysql database pw")
	flag.StringVar(&MYSQL_HOST, "mysql-host", "127.0.0.1", "the mysql database host")
	flag.StringVar(&MYSQL_PORT, "mysql-port", "3306", "the mysql database port")
	flag.StringVar(&STRAVA_ACCESS_TOKEN, "strava-access-token", "", "strava provided access token")
	flag.StringVar(&STRAVA_CLIENT_ID, "strava-client-id", "", "strava provided client id")
	flag.StringVar(&STRAVA_CLIENT_SECRET, "strava-client-secret", "", "strava provided client secret")
	flag.StringVar(&HMAC_KEY, "hmac-key", "abc123", "random string used for hmac sum")
	flag.DurationVar(&POLL_INTERVAL, "poll-interval", time.Hour*12, "set how often we should query Strava to update the runs for each user")
	flag.Int64Var(&EARLIEST_POLL_UNIX, "earliest-poll-unix", 1420070400, "prevent server from querying data older than this unix timestamp. Default 2015-01-01.")
	flag.DurationVar(&COOKIE_EXPIRY, "cookie-expiry", time.Hour*168, "set the expiry time on cookies. ex: 5h30m")

	flagenv.Parse()
	warningMissingConfigs()

	dsn := &DataSourceName{}
	dsn.User = MYSQL_USER
	dsn.Password = MYSQL_PW
	dsn.Host = MYSQL_HOST
	dsn.Port = MYSQL_PORT
	dsn.DBName = MYSQL_DB

	var err error
	DB, err = sql.Open("mysql", dsn.String())
	if err != nil {
		log.Fatalf("unable to connect to database. Check mysql-db, mysq-user, and mysql-pw. %v", err)
	}
	if err := DB.Ping(); err != nil {
		log.Fatalf("unable to ping database. Check mysql-db, mysq-user, and mysql-pw. %v", err)
	}
	defer DB.Close()

	go func() {
		// do
		activityUpdator(-1)
		// while
		for {
			select {
			case <-time.Tick(POLL_INTERVAL):
				log.Println("running scheduled activityUpdator")
				activityUpdator(-1)
			}
		}
	}()

	log.Printf("starting on :%d", port)

	r := mux.NewRouter()

	r.Handle("/", mwLogRequest(http.HandlerFunc(homeHandler)))
	r.Handle("/token_exchange", mwLogRequest(http.HandlerFunc(tokenHandler)))
	r.Handle("/app", mwLogRequest(http.HandlerFunc(appHandler)))

	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), r); err != nil {
		log.Println("unexpected error - %v", err)
	}
}

// activityUpdator updates the activites for a user, or all users if -1 is passed in
func activityUpdator(limitToUserID int) {
	log.Println("running activityUpdator...")
	limitQuery := ""
	if limitToUserID > 0 {
		limitQuery = fmt.Sprintf(" where id=%d", limitToUserID)
	}

	rows, err := DB.Query("select strava_id, oauth_token, updated_at from users" + limitQuery)
	if err != nil {
		log.Printf("error querying database - %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var stravaID int
		var oAuthToken string
		var updatedAt time.Time
		if err := rows.Scan(&stravaID, &oAuthToken, &updatedAt); err != nil {
			log.Printf("error scanning for oauth token - %v", err)
		}
		activities := listAthleteActivities(oAuthToken, updatedAt.Unix())
		for _, activity := range activities {
			if activity.Type != "Run" {
				continue
			}
			startTime, err := time.Parse("2006-01-02T15:04:05Z", activity.StartDate)
			if err != nil {
				log.Printf("error parsing time from activities - %v", err)
				continue
			}
			startDate := startTime.Format(MysqlDateFormat)
			now := time.Now().Format(MysqlDateFormat)
			_, err = DB.Exec(`insert into activities (strava_id, distance, start_date, created_at) values (?, ?, ?, ?) ON DUPLICATE KEY UPDATE strava_id=strava_id`, activity.ID, activity.Distance, startDate, now)
			if err != nil {
				log.Printf("error inserting into activities - %v", err)
				continue
			}
			_, err = DB.Exec(`update users set last_activity_update=? where strava_id=? limit 1`, now, stravaID)
			if err != nil {
				log.Printf("error updating user with activity - %v", err)
				continue
			}
		}

	}
	if err := rows.Err(); err != nil {
		log.Printf("error post scan for oauth token - %v", err)
	}
	log.Println("activityUpdator complete")
}

func listAthleteActivities(oAuthToken string, startUnix int64) []Activity {
	var activities []Activity

	cli := &http.Client{}
	requestQuery := fmt.Sprintf("?after=%d", EARLIEST_POLL_UNIX)
	if startUnix > 0 {
		requestQuery = fmt.Sprintf("?after=%d", startUnix)
	}
	req, err := http.NewRequest("GET", "https://www.strava.com/api/v3/athlete/activities"+requestQuery, strings.NewReader(""))
	if err != nil {
		log.Printf("error setting up new request to activities - %v", err)
		return activities
	}
	defer req.Body.Close()

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", oAuthToken))
	resp, err := cli.Do(req)
	if err != nil {
		log.Printf("error getting response for activities - %v", err)
		return activities
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error reading response body for activities - %v", err)
		return activities
	}
	if resp.StatusCode > 300 {
		log.Printf("unexected response getting activities - %s %s", gencurl.FromRequest(req), string(body))
		return activities
	}

	err = json.Unmarshal(body, &activities)
	if err != nil {
		log.Printf("error marshalling activities  %s - %v", string(body), err)
		return activities
	}

	return activities
}

func checkAndSetUser(stravaID int, email string, oAuthToken string) {
	var ID int
	var previousEmail string
	var previousOAuthToken string
	err := DB.QueryRow(`select id, email, oauth_token from users where strava_id=?`, stravaID).Scan(&ID, &previousEmail, &previousOAuthToken)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("error checking if user exists - %v", err)
		return
	}
	now := time.Now().Format(MysqlDateFormat)

	if ID == 0 {
		result, err := DB.Exec(`insert into users (strava_id, email, oauth_token, updated_at, created_at) values (?, ?, ?, ?, ?)`, stravaID, email, oAuthToken, now, now)
		if err != nil {
			log.Printf("error inserting new users into database - %v", err)
			return
		}
		insertedID, err := result.LastInsertId()
		ID = int(insertedID)
		if err != nil {
			log.Printf("error getting inserted id - %v")
			return
		}
	} else if email != previousEmail || oAuthToken != previousOAuthToken {
		_, err := DB.Exec(`update user set email=?, oauth_token=?, updated_at=? where strava_id=? limit 1`, email, oAuthToken, now)
		if err != nil {
			log.Printf("error updating user record in database - %v", err)
			return
		}
	}

	activityUpdator(ID)
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

	// **************************************************************
	// make sure user is set up in the db - can be done in background

	go checkAndSetUser(OAuthData.StravaAthlete.ID, OAuthData.StravaAthlete.Email, OAuthData.AccessToken)

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

// Constructs the dataSourceName string
type DataSourceName struct {
	User, Password, Host, Port, DBName, Raw string
}

// Method to get the constructed string
func (d *DataSourceName) String() string {
	// username:password@protocol(address)/dbname?param=value
	if len(d.Raw) > 0 {
		// mutate the DataSourceObject for logging elsewhere
		// we could populate the whole object, but yagni
		s := strings.Split(d.Raw, "/")
		d.DBName = s[len(s)-1]

		return d.Raw
	}

	var hostAndPort string
	if len(d.Port) > 0 {
		hostAndPort = fmt.Sprintf("@tcp(%s:%s)", d.Host, d.Port)
	} else {
		hostAndPort = d.Host
	}

	var pw string
	if len(d.Password) > 0 {
		pw = ":" + d.Password
	}

	return fmt.Sprintf("%s%s%s/%s?parseTime=true", d.User, pw, hostAndPort, d.DBName)
}
