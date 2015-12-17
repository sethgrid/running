package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
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
var STRAVA_BASE_URL string

var CROWDRISE_API_KEY string
var CROWDRISE_API_SECRET string
var CROWDRISE_BASE_URL string

var COOKIE_EXPIRY time.Duration // how long the cookie will be valid
var EARLIEST_POLL_UNIX int64    // the earliest unix timestamp for which we will try to get running info
var POLL_INTERVAL time.Duration // how often to update / sync our records
var HMAC_KEY string             // for signing the cookie to detect tampering

// in-app set up
const (
	AuthCookieName  = "auth_cookie"
	MysqlDateFormat = "2006-01-02 15:04:05"
	DateAsYMD       = "2006-01-02"

	// used in summary endpoint and functions
	ErrBadRequest = "bad request - invalid id or bearer token"
	ErrDB         = "database error occured"
)

// DB is concurrent access safe
var DB *sql.DB

// StravaOAuthTokenResponse is the data we get back after validating a user.
// Additionally, this is the data stored to the `AuthCookieName` cookie for frontend use.
type StravaOAuthTokenResponse struct {
	AccessToken   string  `json:"access_token"`
	StravaAthlete Athlete `json:"athlete"`
}

// Athlete represents athlete data from strava. We won't use most of this.
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
	TotalElevationGain float32 `json:"total_elevation_gain"`
	Type      string  `json:"type"`
	StartDate string  `json:"start_date"` // 2013-08-24T00:04:12Z
}

func main() {
	// ****************************
	// pull in configs and validate

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
	flag.StringVar(&STRAVA_BASE_URL, "strava-base-url", "https://www.strava.com", "strava scheme and domain")
	flag.StringVar(&CROWDRISE_API_KEY, "crowdrise-api-key", "", "crowdrise provided api key")
	flag.StringVar(&CROWDRISE_API_SECRET, "crowdrise-api-secret", "", "crowdrise provided api secret")
	flag.StringVar(&CROWDRISE_BASE_URL, "crowdrise-base-url", "https://www.crowdrise.com", "crowdrise scheme and domain")
	flag.StringVar(&HMAC_KEY, "hmac-key", "abc123", "random string used for hmac sum")
	flag.DurationVar(&POLL_INTERVAL, "poll-interval", time.Hour*12, "set how often we should query Strava to update the runs for each user")
	flag.Int64Var(&EARLIEST_POLL_UNIX, "earliest-poll-unix", 1420070400, "prevent server from querying data older than this unix timestamp. Default 2015-01-01.")
	flag.DurationVar(&COOKIE_EXPIRY, "cookie-expiry", time.Hour*168, "set the expiry time on cookies. ex: 5h30m")

	flagenv.Parse()
	warningMissingConfigs()

	// ********************
	// set up db connection

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

	// ****************************************************
	// make sure we stay in sync with user data from strava

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

	// ********************
	// set up server routes

	log.Printf("starting on :%d", port)

	r := mux.NewRouter()
	r.StrictSlash(false)
	// set up the file server to serve public assets
	assets := http.FileServer(http.Dir("assets"))
	r.PathPrefix("/assets/").Handler(mwLogRequest(http.StripPrefix("/assets/", assets)))

	// unauthenticated HTML endpoints
	r.Handle("/", mwLogRequest(http.HandlerFunc(homeHandler)))
	r.Handle("/token_exchange", mwLogRequest(http.HandlerFunc(tokenHandler)))
	r.Handle("/register", mwLogRequest(http.HandlerFunc(registerHandler)))

	// authenticated HTML endpoints
	r.Handle("/app", mwLogRequest(mwAuthenticated(http.HandlerFunc(appHandler))))

	// authenticated JSON endpoints via bearer token
	r.Handle("/user/{id:[0-9]+}/summary", mwLogRequest(http.HandlerFunc(userSummaryHandler)))
	r.Handle(`/crowdrise/{rest:[a-zA-Z0-9=\-\_/]+}`, mwLogRequest(http.HandlerFunc(crowdRiseReverseProxyHandler)))

	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), r); err != nil {
		log.Println("unexpected error serving application - %v", err)
	}
}

// activityUpdator updates the activites for a user, or all users if -1 is passed in
func activityUpdator(limitToUserID int) {
	log.Println("running activityUpdator...")
	limitQuery := ""
	if limitToUserID > 0 {
		limitQuery = fmt.Sprintf(" where id=%d", limitToUserID)
	}

	rows, err := DB.Query("select id, strava_id, oauth_token, updated_at from users" + limitQuery)
	if err != nil {
		log.Printf("error querying database - %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var userID int
		var stravaID int
		var oAuthToken string
		var updatedAt time.Time
		if err := rows.Scan(&userID, &stravaID, &oAuthToken, &updatedAt); err != nil {
			log.Printf("error scanning for oauth token - %v", err)
		}
		activities := listAthleteActivities(oAuthToken, EARLIEST_POLL_UNIX)
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
			_, err = DB.Exec(`insert into activities (user_id, strava_id, distance, elevation, start_date, created_at) values (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE user_id = user_id, strava_id=strava_id, distance=distance, elevation=elevation, start_date=start_date`, userID, activity.ID, activity.Distance, activity.TotalElevationGain, startDate, now)
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

// listAthleteActivities grabs activities from Strava
func listAthleteActivities(oAuthToken string, startUnix int64) []Activity {
	var activities []Activity
	var allActivities []Activity
	var newStartUnix int64

	cli := &http.Client{}
	requestQuery := fmt.Sprintf("?per_page=200&after=%d", EARLIEST_POLL_UNIX)
	if startUnix > 0 {
		requestQuery = fmt.Sprintf("?per_page=200&after=%d", startUnix)
	}
	results := 1
	for results > 0 {
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
		results = len(activities)
		if results > 0 {
			allActivities = append(allActivities,activities...)
			newStartDate, err := time.Parse("2006-01-02T15:04:05Z",activities[len(activities)-1].StartDate)
			if err != nil {
					log.Printf("error parsing time from activities - %v", err)
					continue
				}
			newStartUnix = newStartDate.Unix()
			requestQuery = fmt.Sprintf("?per_page=200&after=%d", newStartUnix)
		}
	}

	return allActivities
}

// checkAndSetUser will insert a user if they do not exist, update them if their email or oAuthToken has changed, or do nothing.
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

// userSummaryHandler grabs locally stored data for the user and does not need to be behind mwAuthenticated middleware
func userSummaryHandler(w http.ResponseWriter, r *http.Request) {
	idStr, ok := mux.Vars(r)["id"]
	if !ok {
		errJSONHandler(w, r, http.StatusBadRequest, "missing user id")
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		log.Printf("error converting id to string - %v", err)
		errJSONHandler(w, r, http.StatusBadRequest, "unable to read numerical user id")
		return
	}
	parts := strings.Split(r.Header.Get("Authorization"), " ")
	if len(parts) != 2 {
		errJSONHandler(w, r, http.StatusBadRequest, "unable to get authorization header bearer token")
		return
	}
	passedInToken := parts[1]

	requestBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("error reading request body in summary handler - %v", err)
		errJSONHandler(w, r, http.StatusBadRequest, "unable to read request body")
		return
	}
	var RequestBody struct {
		StartDate string `json:"start_date"`
	}
	err = json.Unmarshal(requestBody, &RequestBody)
	if err != nil && len(requestBody) > 0 {
		log.Printf("error unmarshalling request body in summary handler - %v", err)
		errJSONHandler(w, r, http.StatusBadRequest, "make sure you are returning start_date set to YYYY-MM-DD")
		return
	}

	startTime := time.Unix(EARLIEST_POLL_UNIX, 0)
	if RequestBody.StartDate != "" {
		startTime, err = time.Parse("2006-01-02", RequestBody.StartDate)
		if err != nil {
			log.Printf("error parsing date format in request body in summary handler - %v", err)
			errJSONHandler(w, r, http.StatusBadRequest, "please use the date format YYYY-MM-DD, ex: 2006-01-02")
			return
		}
	}

	summary, err := getSummary(id, passedInToken, startTime)
	if err != nil && err.Error() == ErrDB {
		errJSONHandler(w, r, http.StatusInternalServerError, "unexpected database error preparing summary")
		return
	} else if err != nil && err.Error() == ErrBadRequest {
		errJSONHandler(w, r, http.StatusBadRequest, "invalid id or bearer token")
		return
	} else if err != nil {
		errJSONHandler(w, r, http.StatusInternalServerError, "unexpected error preparing summary")
		return
	}

	if err = json.NewEncoder(w).Encode(summary); err != nil {
		errJSONHandler(w, r, http.StatusInternalServerError, "unexpected error presenting summary")
		return
	}
}

// Summary provides a listing of all days of since the EARLIEST_POLL_UNIX and if those days have been ran.
// It also provides a running total and basic user information
type Summary struct {
	Results           map[string]bool `json:"results"`
	DaysRan           int             `json:"days_ran"`
	UserID            int             `json:"user_id"`
	Email             string          `json:"email"`
	StravaID          int             `json:"strava_id"`
	CrowdRiseUsername string          `json"crowdrise_username"`
	Firstname         string          `json:"firstname"`
	Lastname          string          `json:"lastname"`
}

// getSummary finds all matching activities in the db for a given strava id and token.
func getSummary(stravaID int, oAuthToken string, start time.Time) (Summary, error) {
	var summary Summary
	summary.Results = make(map[string]bool)

	// verify that this user exists in our records
	var internalID int
	var email, firstname, lastname string
	var crowdriseUsername sql.NullString
	checkQuery := "select id, email, crowdrise_username, firstname, lastname from users where users.strava_id=? and users.oauth_token=?"
	err := DB.QueryRow(checkQuery, stravaID, oAuthToken).Scan(&internalID, &email, &crowdriseUsername, &firstname, &lastname)
	if err != nil && err == sql.ErrNoRows {
		log.Printf("error finding any locally stored users for strava id %d with given token", stravaID)
		return summary, errors.New(ErrBadRequest)
	} else if err != nil {
		log.Printf("error checking for user and bearer token - %v", err)
		return summary, err
	}

	// get user's activities
	activitiesQuery := "select activities.start_date from users left join activities on users.id=activities.user_id where users.strava_id=? and activities.start_date>?"

	rows, err := DB.Query(activitiesQuery, stravaID, start.Format(MysqlDateFormat))
	if err != nil {
		log.Printf("error getting local activity records for strava id %d - %v", stravaID, err)
		return summary, errors.New(ErrDB)
	}

	// seed the return
	date := start
	for date.Unix() < time.Now().Unix() {
		summary.Results[start.Format(DateAsYMD)] = false
		date = date.Add(time.Hour * 24)
	}

	daysRan := 0
	for rows.Next() {
		var start_date time.Time
		if err := rows.Scan(&start_date); err != nil {
			log.Printf("error scanning for start_date - %v", err)
			continue
		}
		if alreadyRan, exists := summary.Results[start_date.Format(DateAsYMD)]; !exists || alreadyRan == false {
			// only increment days ran if this is a new run on a new day
			daysRan++
		}
		summary.Results[start_date.Format(DateAsYMD)] = true

	}
	summary.DaysRan = daysRan
	summary.UserID = internalID
	summary.Email = email
	summary.StravaID = stravaID
	summary.CrowdRiseUsername = crowdriseUsername.String
	summary.Firstname = firstname
	summary.Lastname = lastname

	return summary, nil
}

// EventTotal provides a running total of all statistics for the entire event
type EventTotal struct {
	Participants	  int 			  `json:"participants"`
	MetersRun		  float32 		  `json:"metersrun"`
	MilesRun          float32         `json:"milesrun"`
	MetersGained	  float32 		  `json:"metersgained"`
}

// getEventTotal returns running totals since a given start date for the entire event
func getEventTotal(start time.Time) (EventTotal, error) {
	var eventTotal EventTotal
	activitiesQuery := "select count(distinct users.ID) as participants, sum(ifnull(Distance,0.0)) as metersrun, sum(ifnull(Elevation,0.0)) as metersgained from users left join activities on users.id = activities.user_id where start_date > ?"
	var participants int
	var metersrun float32
	var metersgained float32
	err := DB.QueryRow(activitiesQuery, start.Format(MysqlDateFormat)).Scan(&participants, &metersrun, &metersgained)
	if err != nil {
		log.Printf("error getting event totals from database - %v", err)
		return eventTotal, errors.New(ErrDB)
	}

	eventTotal.Participants = participants
	eventTotal.MetersRun = metersrun
	eventTotal.MilesRun = metersrun/1609.34
	eventTotal.MetersGained = metersgained

	return eventTotal, nil 
}

// LeaderboardEntry provides a total of meters gained, miles run, and days run by user
type LeaderboardEntry struct {
	StravaId int `json:"stravaid"`
	MilesRun float32 `json:"milesrun"`
	MetersGained float32 `json:"metersgained"`
	DaysRun int `json:"daysrun"`
}

func getLeaderboardData(start time.Time) ([]LeaderboardEntry, error) {
	var leaderboardData []LeaderboardEntry
	leaderboardQuery := "select users.strava_id, count(distinct activities.start_date) as daysrun, sum(ifnull(Distance,0.0)) as metersrun, sum(ifnull(Elevation,0.0)) as metersgained FROM users inner join activities on users.id = activities.user_id where start_date > ? group by users.strava_id"
	var strava_id int
	var metersrun float32
	var metersgained float32
	var daysrun int
	rows, err := DB.Query(leaderboardQuery, start.Format(MysqlDateFormat))
	if err != nil {
		log.Printf("error getting leaderboard data from database - %v", err)
		return leaderboardData, errors.New(ErrDB)
	}
	for rows.Next() {
		if err := rows.Scan(&strava_id, &daysrun, &metersrun, & metersgained); err != nil {
			log.Printf("error scanning for leaderboard data - %v", err)
			continue
		}
		var e LeaderboardEntry
		e.StravaId = strava_id
		e.MilesRun = metersrun/1609.34
		e.MetersGained = metersgained
		e.DaysRun = daysrun
		leaderboardData = append(leaderboardData, e)
	}
	return leaderboardData, nil	
}

// homeHandler presents the index.html template
func homeHandler(w http.ResponseWriter, r *http.Request) {
	templates := []string{"base.html","index.html"}
	t, err := template.ParseFiles(templates...)
	if err != nil {
		log.Println("unable to parse index.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing templates")
	}
	tm := time.Date(2015, time.January, 1, 0, 0, 0, 0, time.UTC)
	totals, err := getEventTotal(tm.Local())
	leaderboardData, err := getLeaderboardData(tm.Local())
	data := struct {
		StravaClientID string
		Participants int
		MetersRun float32
		MilesRun int
		ThousandFeetGained int
		MetersGained float32
		LeaderboardData []LeaderboardEntry
	}{
		StravaClientID: STRAVA_CLIENT_ID,
		Participants: totals.Participants,
		MetersRun: totals.MetersRun,
		MilesRun: int(totals.MetersRun/1609.34),
		ThousandFeetGained: int(totals.MetersGained*3.28084/1000),
		MetersGained: totals.MetersGained,
		LeaderboardData: leaderboardData,
	}

	err = t.Execute(w, data)
	if err != nil {
		log.Printf("error executing template in homeHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing templates")
	}
}

// registerHandler presents the register.html template
func registerHandler(w http.ResponseWriter, r *http.Request) {
	templates := []string{"base.html","register.html"}
	
	//Check to see whether the user is cookied
	cookieData, err := readAuthCookie(r)
	if err != nil {
		log.Println("user not cookied, showing full registration page")
		templates = append(templates,"register-all.html")
	} else {
		log.Println("user cookied, showing step 2 page only")
		templates = append(templates,"register-step-2-only.html")
	}
	_ = cookieData

	data := struct {
		StravaClientID string
	}{
		StravaClientID: STRAVA_CLIENT_ID,
	}
	t, err := template.ParseFiles(templates...)
	if err != nil {
		log.Println("unable to parse register.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing templates")
	}
	err = t.Execute(w, data)
	if err != nil {
		log.Printf("error executing template in registerHandler - %v", err)
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

	code := r.URL.Query().Get("code")
	if code == "" {
		errHandler(w, r, http.StatusBadRequest, "missing code parameter")
		return
	}

	OAuthData, rawBody, err := StravaOAuthTokenEndpoint(code)
	if err != nil {
		errHandler(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	// **************************************************************
	// make sure user is set up in the db - can be done in background

	go checkAndSetUser(OAuthData.StravaAthlete.ID, OAuthData.StravaAthlete.Email, OAuthData.AccessToken)

	// ****************************
	// set AuthCookieName and redirect

	mac := hmac.New(sha256.New, []byte(HMAC_KEY))
	_, err = mac.Write(rawBody)
	if err != nil {
		log.Printf("unable to encode data for auth cookie - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "error encoding auth cookie")
		return
	}

	cookie := http.Cookie{}
	cookie.Name = AuthCookieName
	cookie.Value = padBase64(base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s%s%s", string(rawBody), "::hmac::", base64.StdEncoding.EncodeToString((mac.Sum(nil)))))))
	cookie.Expires = time.Now().Add(COOKIE_EXPIRY)

	http.SetCookie(w, &cookie)
	//Handle redirection based on state
	if state == "newreg" {
		log.Printf("forwarding request to /register for part 2")
		w.Header().Set("Location", "/register")
		w.WriteHeader(301)
		w.Write([]byte("Redirecting to /register..."))
	} else {
		log.Printf("forwarding request to /app")
		w.Header().Set("Location", "/app")
		w.WriteHeader(301)
		w.Write([]byte("Redirecting to /app..."))
	}
}

// crowdRiseSignupHandler is invoked in the reverse proxy and captures important details
// that our system wants about the signup if succuessful
func crowdRiseSignupHandler(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("issue reading signup body - %v", err)
		errJSONHandler(w, r, http.StatusInternalServerError, "internal error reading the signup body")
		return
	}
	b = append(b, []byte(fmt.Sprintf("&api_key=%s&api_secret=%s", CROWDRISE_API_KEY, CROWDRISE_API_SECRET))...)
	log.Printf("changing body to %s", b)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
	r.ContentLength = int64(len(b))

	// get important parts. Working with strings because it is easier and the performance hit is no biggy here
	parts := strings.Split(string(b), "&")
	var firstname string // collected in the request
	var lastname string  // collected in the request
	for _, part := range parts {
		keyValue := strings.Split(part, "=")
		if keyValue[0] == "first_name" {
			firstname = keyValue[1]
		}
		if keyValue[0] == "last_name" {
			lastname = keyValue[1]
		}
	}

	resp, err := http.Post(CROWDRISE_BASE_URL+"/api/signup", "application/x-www-form-urlencoded", bytes.NewBuffer(b))
	if err != nil {
		log.Printf("error signing up user - %q", err.Error())
		errJSONHandler(w, r, http.StatusInternalServerError, "error signing up with crowdrise")
		return
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error reading response body from signup request - %q", err.Error())
		errJSONHandler(w, r, http.StatusInternalServerError, "error reading response from crowdrise")
		return
	}

	if resp.StatusCode > 300 {
		log.Printf("unexpected response from crowdrise signup: %s", data)
		errJSONHandler(w, r, http.StatusInternalServerError, "unexpected result from crowdrise")
		return
	}

	var signupResponse struct {
		Status string `json:"status"`
		Result []struct {
			UserCreated       bool   `json:"user_created"`
			Username          string `json:"username"`
			UserID            string `json:"user_id"`
			CompleteSignupURL string `json:"complete_signup_url"`
			ErrorID           string `json:"error_id"`
			Error             string `json:"error"`
		} `json:"result"`
	}
	err = json.Unmarshal(data, &signupResponse)
	if err != nil {
		log.Printf("error unmarshalling signup response for %q: %q", string(data), err.Error())
		errJSONHandler(w, r, http.StatusInternalServerError, "unable to parse result from crowdrise signup")
		return
	}

	if !signupResponse.Result[0].UserCreated {
		log.Printf("error - user not created - %s", string(data))
		errJSONHandler(w, r, http.StatusInternalServerError, fmt.Sprintf("crowdrise did not create the user - %s", signupResponse.Result[0].Error))
		return
	}

	authParts := strings.Split(r.Header.Get("Authorization"), " ")
	if len(authParts) != 2 {
		errJSONHandler(w, r, http.StatusBadRequest, "unable to get authorization header bearer token")
		return
	}
	passedInToken := authParts[1]

	_, err = DB.Exec("update users set crowdrise_username=?, firstname=?, lastname=? where oauth_token=? limit 1", signupResponse.Result[0].Username, firstname, lastname, passedInToken)
	if err != nil {
		log.Printf("error updating user record with crowdrise information - %q", err.Error())
		errJSONHandler(w, r, http.StatusInternalServerError, "internal storage error saving crowdrise information")
		return
	}

	// pass the data back to the front end
	w.Write(data)
}

// crowdRiseSignupHandler is invoked in the reverse proxy and captures important details
// that our system wants about the signup if succuessful
func crowdRiseSignupHandler(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("issue reading signup body - %v", err)
		errJSONHandler(w, r, http.StatusInternalServerError, "internal error reading the signup body")
		return
	}
	b = append(b, []byte(fmt.Sprintf("&api_key=%s&api_secret=%s", CROWDRISE_API_KEY, CROWDRISE_API_SECRET))...)
	log.Printf("changing body to %s", b)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
	r.ContentLength = int64(len(b))

	// get important parts. Working with strings because it is easier and the performance hit is no biggy here
	parts := strings.Split(string(b), "&")
	var firstname string // collected in the request
	var lastname string  // collected in the request
	for _, part := range parts {
		keyValue := strings.Split(part, "=")
		if keyValue[0] == "first_name" {
			firstname = keyValue[1]
		}
		if keyValue[0] == "last_name" {
			lastname = keyValue[1]
		}
	}

	resp, err := http.Post(CROWDRISE_BASE_URL+"/api/signup", "application/x-www-form-urlencoded", bytes.NewBuffer(b))
	if err != nil {
		log.Printf("error signing up user - %q", err.Error())
		errJSONHandler(w, r, http.StatusInternalServerError, "error signing up with crowdrise")
		return
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error reading response body from signup request - %q", err.Error())
		errJSONHandler(w, r, http.StatusInternalServerError, "error reading response from crowdrise")
		return
	}

	if resp.StatusCode > 300 {
		log.Printf("unexpected response from crowdrise signup: %s", data)
		errJSONHandler(w, r, http.StatusInternalServerError, "unexpected result from crowdrise")
		return
	}

	var signupResponse struct {
		Status string `json:"status"`
		Result []struct {
			UserCreated       bool   `json:"user_created"`
			Username          string `json:"username"`
			UserID            int    `json:"user_id"`
			CompleteSignupURL string `json:"complete_signup_url"`
			ErrorID           string `json:"error_id"`
			Error             string `json:"error"`
		} `json:"result"`
	}
	err = json.Unmarshal(data, &signupResponse)
	if err != nil {
		log.Printf("error unmarshalling signup response for %q: %q", string(data), err.Error())
		errJSONHandler(w, r, http.StatusInternalServerError, "unable to parse result from crowdrise signup")
		return
	}

	if !signupResponse.Result[0].UserCreated {
		log.Printf("error - user not created - %s", string(data))
		errJSONHandler(w, r, http.StatusInternalServerError, fmt.Sprintf("crowdrise did not create the user - %s", signupResponse.Result[0].Error))
		return
	}

	authParts := strings.Split(r.Header.Get("Authorization"), " ")
	if len(authParts) != 2 {
		errJSONHandler(w, r, http.StatusBadRequest, "unable to get authorization header bearer token")
		return
	}
	passedInToken := authParts[1]

	_, err = DB.Exec("update users set crowdrise_username=?, firstname=?, lastname=? where oauth_token=? limit 1", signupResponse.Result[0].Username, firstname, lastname, passedInToken)
	if err != nil {
		log.Printf("error updating user record with crowdrise information - %q", err.Error())
		errJSONHandler(w, r, http.StatusInternalServerError, "internal storage error saving crowdrise information")
		return
	}

	// pass the data back to the front end
	w.Write(data)
}

// crowdRiseReverseProxyHandler is a reverse proxy that appends the api user and token to a request and forwards it.
// use case: the user is logged in and the js frontend is making a request for
// data to crowdRise. Validate the email/oauth_token combo exists in the db
// based on the email in the cookie and
// the reverse proxy the request.
func crowdRiseReverseProxyHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.Header.Get("Authorization"), " ")
	if len(parts) != 2 {
		errJSONHandler(w, r, http.StatusBadRequest, "unable to get authorization header bearer token")
		return
	}
	passedInToken := parts[1]

	var email string
	err := DB.QueryRow("select email from users where oauth_token=? limit 1", passedInToken).Scan(&email)
	if err != nil {
		if err == sql.ErrNoRows {
			errJSONHandler(w, r, http.StatusBadRequest, "invalid token, no associated user found")
			return
		}
		log.Println("error with database validating token for reverse proxy")
		errJSONHandler(w, r, http.StatusBadRequest, "internal database error")
		return
	}

	fwdStr, ok := mux.Vars(r)["rest"]
	if !ok {
		errJSONHandler(w, r, http.StatusBadRequest, "missing forwarding url")
		return
	}

	switch fwdStr {
	case "api/check_if_user_exists":
	case "api/heartbeat":
	case "api/signup":
		crowdRiseSignupHandler(w, r)
		return
	case "api/url_data":
	default:
		log.Println("non-whitelist url attempted: %s", fwdStr)
		errJSONHandler(w, r, http.StatusBadRequest, "proxy request not allowed")
		return
	}

	var directorErr error
	director := func(req *http.Request) {
		// handle both cases where we got `http://hostname` or `hostname`
		parts := strings.Split(CROWDRISE_BASE_URL, "://")
		var scheme string
		var host string
		if len(parts) == 1 { // there was no scheme in the config
			scheme = "http"
			host = parts[0]
		} else if len(parts) >= 2 { // there was a scheme in the config
			scheme = parts[0]
			host = parts[1]
		} else {
			log.Printf("issue splitting host on :// - %s", CROWDRISE_BASE_URL)
			directorErr = errors.New("internal error reading config")
			return
		}
		log.Printf("host %s, scheme %s", host, scheme)
		req = r
		req.Host = host
		req.URL.Scheme = scheme
		req.URL.Host = host
		req.URL.Path = strings.Replace(req.URL.Path, "/crowdrise/", "/", 1)

		// uncomment to see sample curl request for debugging
		// must be commented out to work as it drains the request
		// log.Println(gencurl.FromRequest(req))
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("issue reading proxy body - %v", err)
		directorErr = errors.New("internal error reading proxy body")
		return
	}
	b = append(b, []byte(fmt.Sprintf("&api_key=%s&api_secret=%s", CROWDRISE_API_KEY, CROWDRISE_API_SECRET))...)
	log.Printf("changing body to %s", b)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
	r.ContentLength = int64(len(b))

	proxy := &httputil.ReverseProxy{Director: director}
	proxy.ServeHTTP(w, r)
	if directorErr != nil {
		errJSONHandler(w, r, http.StatusInternalServerError, directorErr.Error())
		return
	}

	log.Printf("crowdrise proxy request complete")
}

// StravaOAuthTokenEndpoint takes in code Strava sends to the domain callback URL and sends it back to Strava to get OAuth data.
func StravaOAuthTokenEndpoint(code string) (StravaOAuthTokenResponse, []byte, error) {
	var OAuthData StravaOAuthTokenResponse

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
		return OAuthData, nil, errors.New("unable to prepare data for oauth token request")
	}

	resp, err := http.Post(fmt.Sprintf("%s/oauth/token", STRAVA_BASE_URL), "application/json", bytes.NewReader(b))
	if err != nil {
		log.Println("error posting to strava oauth token endpoint - %v", err)
		return OAuthData, nil, errors.New("error communicating with strava")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return OAuthData, nil, errors.New("unable to read strava response")
	}

	if resp.StatusCode > 300 {
		log.Printf("unexpected result from strava getting token: [%d] %s", resp.StatusCode, string(body))
		return OAuthData, nil, errors.New("unexpected result from strava")
	}

	err = json.Unmarshal(body, &OAuthData)
	if err != nil {
		log.Printf("unable to unmarshal oauth data - %v", err)
		return OAuthData, nil, errors.New("unexpected result structure from strava")
	}

	return OAuthData, body, nil
}

// appHandler presents the app.html template and should be behind the mwAuthenticated middleware
func appHandler(w http.ResponseWriter, r *http.Request) {
	templates := []string{"base.html","app.html"}
	t, err := template.ParseFiles(templates...)
	if err != nil {
		log.Println("unable to parse app.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing app template")
		return
	}

	cookieData, err := readAuthCookie(r)
	if err != nil {
		log.Println("error reading cookie data in appHandler")
		authErrHandler(w, r, "unable to read cookie data in app.html. Please log back in.")
		return
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
		return
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

// errJSONHandler logs and writes a json message and sets a status code
func errJSONHandler(w http.ResponseWriter, r *http.Request, statusCode int, msg string) {
	log.Printf("%s - [%d] %s", r.URL, statusCode, msg)
	w.WriteHeader(statusCode)
	returnMsg := fmt.Sprintf(`{"result":"%s"}`, msg)
	w.Write([]byte(returnMsg))
}

// readAuthCookie does nearly identical work to the mwAuthenticated, but does no validation
func readAuthCookie(r *http.Request) (StravaOAuthTokenResponse, error) {
	var cookieData StravaOAuthTokenResponse

	cookie, err := r.Cookie(AuthCookieName)
	if err != nil {
		log.Printf("error obtaining auth cookie - %v", err)
		return cookieData, errors.New("Unable to read cookie data. Please sign back in.")
	}

	decoded, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		log.Printf("error decoding cookie value - %s", string(decoded))
		return cookieData, errors.New("Unable to decode cookie data. Please sign back in.")
	}
	parts := strings.Split(string(decoded), "::hmac::")
	if len(parts) != 2 {
		log.Printf("missing parts on cookie: %s", cookie)
		return cookieData, errors.New("Corrupt cookie data. Please sign back in.")
	}
	marshalled := parts[0]

	err = json.Unmarshal([]byte(marshalled), &cookieData)
	if err != nil {
		log.Printf("error marshalling cookie data - %v", err)
		return cookieData, errors.New("unable to decode coodie data. Please sign back in.")
	}

	return cookieData, nil
}

// mwAuthendicated prevents not authenticated users from proceeding.
// Authentication is based on the existance of a non-tampered with cookie.
// The cookie is signed via HMAC and verified before letting the request through
// to the next handler. Logic is nearly identical to readAuthCookie.
func mwAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		originalJSONToken := parts[0]
		signedMac, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			log.Printf("error base64 decoding passed in hmac value - %v", err)
			authErrHandler(w, r, "Unable to decode cookie signature. Please sign back in.")
			return
		}
		computedMac := hmac.New(sha256.New, []byte(HMAC_KEY))
		_, _ = computedMac.Write([]byte(originalJSONToken))
		if !hmac.Equal(computedMac.Sum(nil), []byte(signedMac)) {
			log.Printf("macs do not match")
			authErrHandler(w, r, "Invalid cookie data. Please sign back in.")
			return
		}

		var cookieData StravaOAuthTokenResponse
		err = json.Unmarshal([]byte(originalJSONToken), &cookieData)
		if err != nil {
			log.Printf("error marshalling cookie data - %v", err)
			authErrHandler(w, r, "unable to decode coodie data. Please sign back in.")
			return
		}

		next.ServeHTTP(w, r)
	})
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

// DataSourceName exists to form the DSN (data source name) string
type DataSourceName struct {
	User, Password, Host, Port, DBName, Raw string
}

// String provides the constructed DSN (data source name) string
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

// Reconstitutes padding removed from a base64 string
func padBase64(s string) string {
	l := len(s)
	m := l % 4
	padding := (4 - m) % 4 // use the modulo so that if m == 0, then padding is 0, not 4

	return s + strings.Repeat("=", padding)
}
