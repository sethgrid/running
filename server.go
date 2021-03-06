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
	"html"
	"html/template"
	"io/ioutil"
	"log"
	"math"
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
	"github.com/sendgrid/sendgrid-go"
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

var SENDGRID_API_KEY string
var SENDGRID_TEMPLATE_ID string

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
	ID                 int     `json:"ID"`
	Distance           float32 `json:"distance"`
	TotalElevationGain float32 `json:"total_elevation_gain"`
	Type               string  `json:"type"`
	StartDateLocal     string  `json:"start_date_local"` // 2013-08-24T00:04:12Z
	StartDate          string  `json:"start_date"`
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
	flag.StringVar(&SENDGRID_API_KEY, "sendgrid-api-key", "", "SendGrid API key for sendging welcome email")
	flag.StringVar(&SENDGRID_TEMPLATE_ID, "sendgrid-template-id", "", "SendGrid Tempalte ID for the welcome email")
	flag.StringVar(&HMAC_KEY, "hmac-key", "abc123", "random string used for hmac sum")
	flag.DurationVar(&POLL_INTERVAL, "poll-interval", time.Hour*12, "set how often we should query Strava to update the runs for each user")
	flag.Int64Var(&EARLIEST_POLL_UNIX, "earliest-poll-unix", 1420070400, "prevent server from querying data older than this unix timestamp. Default 2015-01-01.")
	flag.DurationVar(&COOKIE_EXPIRY, "cookie-expiry", time.Hour*168, "set the expiry time on cookies. ex: 5h30m")

	flagenv.Parse()
	warningMissingConfigs()

	// uncomment to test the sending of the welcome email.
	// TODO: delete this
	//if err := SendWelcomeEmail(); err != nil {
	// 	log.Fatalf("unable to send sendgrid email = %q", err.Error())
	// } else {
	// 	log.Fatal("mail sent successfully")
	// }

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
		eventTotalsUpdator()
		// while
		for {
			select {
			case <-time.Tick(POLL_INTERVAL):
				log.Println("running scheduled activityUpdator and eventTotalsUpdator")
				activityUpdator(-1)
				eventTotalsUpdator()
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
	r.Handle("/terms", mwLogRequest(http.HandlerFunc(termsHandler)))
	r.Handle("/about", mwLogRequest(http.HandlerFunc(aboutHandler)))
	r.Handle("/rules", mwLogRequest(http.HandlerFunc(rulesHandler)))
	r.Handle("/privacy", mwLogRequest(http.HandlerFunc(privacyHandler)))
	r.Handle("/waiver", mwLogRequest(http.HandlerFunc(waiverHandler)))
	r.Handle(`/runners/{rest:[0-9]+}`, mwLogRequest(http.HandlerFunc(runnerProfileHandler)))
	r.Handle("/logout", mwLogRequest(http.HandlerFunc(logOutHandler)))

	// authenticated HTML endpoints
	r.Handle("/app", mwLogRequest(mwAuthenticated(http.HandlerFunc(appHandler))))
	r.Handle("/setup", mwLogRequest(mwAuthenticated(http.HandlerFunc(setupHandler))))

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
			startTime, err := time.Parse("2006-01-02T15:04:05Z", activity.StartDateLocal)
			if err != nil {
				log.Printf("error parsing time from activities - %v", err)
				continue
			}
			startDate := startTime.Format(MysqlDateFormat)
			now := time.Now().Format(MysqlDateFormat)
			_, err = DB.Exec(`insert into activities (user_id, strava_id, distance, elevation, start_date, created_at) values (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE distance=?, elevation=?, start_date=?`, userID, activity.ID, activity.Distance, activity.TotalElevationGain, startDate, now, activity.Distance, activity.TotalElevationGain, startDate)
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

func eventTotalsUpdator() {
	log.Println("Running event totals update...")
	// Get the results from Crowdrise by calling a function
	cli := &http.Client{}

	type CrowdriseTeamData []struct {
		TeamID                 string `json:"team_id"`
		TeamName               string `json:"team_name"`
		TeamUsername           string `json:"team_username"`
		DonationAmountOnline   string `json:"total_donations_online_amount"`
		DonationAmountOffline  string `json:"total_donations_offline_amount"`
		DonationCountOnline    string `json:"total_donations_online_count"`
		DonationCountOffline   string `json:"total_donations_offline_count"`
		CharityEIN             string `json:"charity_ein"`
		TeamURL                string `json:"team_url"`
		OfficialTeam           bool   `json:"official_team"`
		HiddenFromEvent        bool   `json:"hidden_from_event"`
		CharityName            string `json:"charity_name"`
		CharityURL             string `json:"charity_url"`
		TeamOrganizerFirstName string `json:"team_organizer_first_name"`
		TeamOrganizerLastName  string `json:"team_organizer_last_name"`
		TeamOrganizerEmail     string `json:"team_organizer_email"`
		TeamOrganizerOrg       string `json:"team_organizer_organization"`
		TeamOrganizerID        string `json:"team_organizer_id"`
		FundraisingCommitment  string `json:"fundraising_commitment"`
		Goal                   string `json:"goal"`
	}

	type CrowdriseTeamResponse struct {
		Status string              `json:"status"`
		Result []CrowdriseTeamData `json:"result"`
	}
	requestQuery := fmt.Sprintf("api_key=%s&api_token=%s", CROWDRISE_API_KEY, CROWDRISE_API_SECRET)
	totals := func() CrowdriseTeamResponse {
		var totals CrowdriseTeamResponse
		req, err := http.NewRequest("GET", "https://www.crowdrise.com/api/get_event_teams/300DaysOfRun/?"+requestQuery, strings.NewReader(""))
		if err != nil {
			log.Printf("error setting up new request to crowdrise event totals - %v", err)
			return totals
		}
		defer req.Body.Close()

		resp, err := cli.Do(req)
		if err != nil {
			log.Printf("error getting response for crowdrise event totals - %v", err)
			return totals
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("error reading response body for crowdrise event totals - %v", err)
			return totals
		}
		if resp.StatusCode > 300 {
			log.Printf("unexected response getting crowdrise event totals - %s %s", gencurl.FromRequest(req), string(body))
			return totals
		}

		err = json.Unmarshal(body, &totals)
		if err != nil {
			log.Printf("error marshalling crowdrise event totals  %s - %v", string(body), err)
			return totals
		}

		return totals
	}()
	for _, total := range totals.Result[0] {
		_, err := DB.Exec(`insert into teams (team_id, total_donations_online_amount, total_donations_offline_amount, total_donations_online_count, total_donations_offline_count, charity_ein, charity_name) values (?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE total_donations_online_amount=?, total_donations_offline_amount=?, total_donations_online_count=?, total_donations_offline_count=?, charity_ein=?, charity_name=?`, total.TeamID, total.DonationAmountOnline, total.DonationAmountOffline, total.DonationCountOnline, total.DonationCountOffline, total.CharityEIN, total.CharityName, total.DonationAmountOnline, total.DonationAmountOffline, total.DonationCountOnline, total.DonationCountOffline, total.CharityEIN, total.CharityName)
		if err != nil {
			log.Printf("error inserting into teams - %v", err)
			continue
		}
	}
	log.Println("eventTotalsUpdator complete")
}

// listAthleteActivities grabs activities from Strava
func listAthleteActivities(oAuthToken string, startUnix int64) []Activity {
	var allActivities []Activity
	var newStartUnix int64

	cli := &http.Client{}
	requestQuery := fmt.Sprintf("?per_page=200&after=%d", EARLIEST_POLL_UNIX)
	if startUnix > 0 {
		requestQuery = fmt.Sprintf("?per_page=200&after=%d", startUnix)
	}
	results := 1
	for results > 0 {
		// call a function so we can use defer statements for closing .Body()
		activities := func() []Activity {
			var activities []Activity
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
		}()
		results = len(activities)
		if results > 0 {
			allActivities = append(allActivities, activities...)
			newStartDate, err := time.Parse("2006-01-02T15:04:05Z", activities[len(activities)-1].StartDate)
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
func checkAndSetUser(stravaID int, email string, firstname string, lastname string, oAuthToken string) {
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
		result, err := DB.Exec(`insert into users (strava_id, email, oauth_token, firstname, lastname, updated_at, created_at) values (?, ?, ?, ?, ?, ?, ?)`, stravaID, email, oAuthToken, firstname, lastname, now, now)
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
	var email string
	var firstname, lastname, crowdriseUsername sql.NullString
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
	defer rows.Close()

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
	summary.Firstname = firstname.String
	summary.Lastname = lastname.String

	return summary, nil
}

// EventTotal provides a running total of all statistics for the entire event
type EventTotal struct {
	Participants       int    `json:"participants"`
	MilesRun           string `json:"milesrun"`
	ThousandFeetGained string `json:"thousandfeetgained"`
	MoneyRaised        string `json:"moneyraised"`
}

// getEventTotal returns running totals since a given start date for the entire event
func getEventTotal(start time.Time) (EventTotal, error) {
	var eventTotal EventTotal
	activitiesQuery := "select act.participants	,act.metersrun ,act.metersgained ,t.moneyraised from (select count(distinct users.ID) as participants ,sum(ifnull(Distance,0.0)) as metersrun ,sum(ifnull(Elevation,0.0)) as metersgained from users left join activities on users.id = activities.user_id and start_date > ?) act cross join (select (sum(ifnull(total_donations_online_amount,0)) + sum(ifnull(total_donations_offline_amount,0))) as moneyraised from teams) t"
	var participants int
	var metersrun, metersgained, moneyraised float64
	err := DB.QueryRow(activitiesQuery, start.Format(MysqlDateFormat)).Scan(&participants, &metersrun, &metersgained, &moneyraised)
	if err != nil {
		log.Printf("error getting event totals from database - %v", err)
		return eventTotal, errors.New(ErrDB)
	}

	eventTotal.Participants = participants
	eventTotal.MilesRun = Comma(int64(metersrun / 1609.34))
	eventTotal.ThousandFeetGained = Comma(int64(metersgained * 3.28084 / 1000))
	eventTotal.MoneyRaised = "$" + Comma(int64(math.Floor(moneyraised+.5)))

	return eventTotal, nil
}

// LeaderboardEntry provides a total of meters gained, miles run, and days run by user
type LeaderboardEntry struct {
	FullName    string `json:"fullname"`
	StravaId    int    `json:"strava_id"`
	MilesRun    string `json:"milesrun"`
	FeetGained  string `json:"feetgained"`
	DaysRun     int    `json:"daysrun"`
	AthleteURL  string `json:"athleteurl"`
	MoneyRaised string `json:"moneyraised"`
}

func getLeaderboardData(start time.Time) ([]LeaderboardEntry, error) {
	var leaderboardData []LeaderboardEntry
	leaderboardQuery := "select users.strava_id, users.firstname, users.lastname, count(distinct date(activities.start_date)) as daysrun, sum(ifnull(Distance,0.0)) as metersrun, sum(ifnull(Elevation,0.0)) as metersgained, (max(ifnull(total_donations_online_amount,0)) + max(ifnull(total_donations_offline_amount,0))) as moneyraised FROM users left join activities on users.id = activities.user_id and start_date > ? left join teams on teams.team_id = users.crowdrise_team_id group by users.strava_id"
	var firstname, lastname string
	var metersrun, metersgained, moneyraised float64
	var daysrun, strava_id int
	rows, err := DB.Query(leaderboardQuery, start.Format(MysqlDateFormat))
	if err != nil {
		log.Printf("error getting leaderboard data from database - %v", err)
		return leaderboardData, errors.New(ErrDB)
	}
	defer rows.Close()

	for rows.Next() {
		if err := rows.Scan(&strava_id, &firstname, &lastname, &daysrun, &metersrun, &metersgained, &moneyraised); err != nil {
			log.Printf("error scanning for leaderboard data - %v", err)
			continue
		}
		var e LeaderboardEntry
		e.StravaId = strava_id
		e.MilesRun = Comma(int64(metersrun / 1609.34))
		e.FeetGained = Comma(int64(metersgained * 3.28084))
		e.DaysRun = daysrun
		e.FullName = firstname + " " + lastname
		e.AthleteURL = "<a href='http://300daysofrun.com/runners/" + strconv.Itoa(strava_id) + "' target='_blank'>" + firstname + " " + lastname + "</a>"
		e.MoneyRaised = "$" + Comma(int64(math.Floor(moneyraised+.5)))
		leaderboardData = append(leaderboardData, e)
	}
	return leaderboardData, nil
}

// homeHandler presents the index.html template
func homeHandler(w http.ResponseWriter, r *http.Request) {
	templates := []string{"templates/base.html", "templates/index.html"}
	t, err := template.ParseFiles(templates...)
	if err != nil {
		log.Println("unable to parse index.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing templates")
	}
	tm := time.Date(2016, time.January, 1, 0, 0, 0, 0, time.UTC)
	totals, err := getEventTotal(tm.Local())
	leaderboardData, err := getLeaderboardData(tm.Local())
	data := struct {
		StravaClientID     string
		Participants       int
		MetersRun          float32
		MilesRun           string
		ThousandFeetGained string
		MetersGained       float32
		MoneyRaised        string
		LeaderboardData    []LeaderboardEntry
	}{
		StravaClientID:     STRAVA_CLIENT_ID,
		Participants:       totals.Participants,
		MilesRun:           totals.MilesRun,
		ThousandFeetGained: totals.ThousandFeetGained,
		LeaderboardData:    leaderboardData,
		MoneyRaised:        totals.MoneyRaised,
	}

	err = t.Execute(w, data)
	if err != nil {
		log.Printf("error executing template in homeHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing templates")
	}
}

// termsHandler presents the terms.html template
func termsHandler(w http.ResponseWriter, r *http.Request) {
	templates := []string{"templates/base.html", "templates/terms.html"}
	t, err := template.ParseFiles(templates...)
	if err != nil {
		log.Println("unable to parse terms.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing templates")
		return
	}

	err = t.Execute(w, nil)
	if err != nil {
		log.Printf("error executing template in termsHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing templates")
		return
	}
}

// aboutHandler presents the terms.html template
func aboutHandler(w http.ResponseWriter, r *http.Request) {
	templates := []string{"templates/base.html", "templates/about.html"}
	t, err := template.ParseFiles(templates...)
	if err != nil {
		log.Println("unable to parse about.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing templates")
		return
	}

	err = t.Execute(w, nil)
	if err != nil {
		log.Printf("error executing template in aboutHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing templates")
		return
	}
}

// rulesHandler presents the terms.html template
func rulesHandler(w http.ResponseWriter, r *http.Request) {
	templates := []string{"templates/base.html", "templates/rules.html"}
	t, err := template.ParseFiles(templates...)
	if err != nil {
		log.Println("unable to parse rules.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing templates")
		return
	}

	err = t.Execute(w, nil)
	if err != nil {
		log.Printf("error executing template in rulesHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing templates")
		return
	}
}

// privacyHandler presents the privacy.html template
func privacyHandler(w http.ResponseWriter, r *http.Request) {
	templates := []string{"templates/base.html", "templates/privacy.html"}
	t, err := template.ParseFiles(templates...)
	if err != nil {
		log.Println("unable to parse privacy.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing templates")
		return
	}

	err = t.Execute(w, nil)
	if err != nil {
		log.Printf("error executing template in privacyHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing templates")
		return
	}
}

// waiverHandler presents the waiver.html template
func waiverHandler(w http.ResponseWriter, r *http.Request) {
	templates := []string{"templates/base.html", "templates/waiver.html"}
	t, err := template.ParseFiles(templates...)
	if err != nil {
		log.Println("unable to parse waiver.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing templates")
		return
	}

	err = t.Execute(w, nil)
	if err != nil {
		log.Printf("error executing template in waiverHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing templates")
		return
	}
}

// registerHandler presents the register.html template
func registerHandler(w http.ResponseWriter, r *http.Request) {
	templates := []string{"templates/base.html", "templates/register.html"}

	//Check to see whether the user is cookied
	cookieData, err := readAuthCookie(r)
	if err != nil {
		log.Println("user not cookied, showing full registration page")
		templates = append(templates, "templates/register-all.html")
	} else {
		//Check to see if the user already has a crowdrise username, and if so, fowrard them to /setup
		var crowdriseID sql.NullString
		err = DB.QueryRow("select crowdrise_id from users where oauth_token=? limit 1", cookieData.AccessToken).Scan(&crowdriseID)
		if crowdriseID.String != "" {
			w.Header().Set("Location", "/setup")
			w.WriteHeader(http.StatusTemporaryRedirect)
			w.Write([]byte("Redirecting to setup..."))
		}
		log.Println("user cookied, showing step 2 page only")
		templates = append(templates, "templates/register-step-2-only.html")
	}

	data := struct {
		StravaClientID string
	}{
		StravaClientID: STRAVA_CLIENT_ID,
	}
	t, err := template.ParseFiles(templates...)
	if err != nil {
		log.Println("unable to parse register.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing templates")
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		log.Printf("error executing template in registerHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing templates")
		return
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

	go checkAndSetUser(OAuthData.StravaAthlete.ID, OAuthData.StravaAthlete.Email, OAuthData.StravaAthlete.FirstName, OAuthData.StravaAthlete.LastName, OAuthData.AccessToken)

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
	cookie.Domain = ".300daysofrun.com"
	http.SetCookie(w, &cookie)
	//Handle redirection based on state
	//For new registrants, check for an existing crowdrise account and use it if present
	if state == "newreg" {
		// Check to see if a Crowdrise account already exists and if so, update the users table
		//if crowdRiseCheckAndSetUser(OAuthData.StravaAthlete.Email, w, r, OAuthData.AccessToken) {
		//	// There was already a crowdrise user, and we updated the users table.
		//	// Drop the user at the setup page to finish their fundraising setup
		//	log.Printf("The person already had a crowdrise account")
		//	w.Header().Set("Location", "/setup")
		//	w.WriteHeader(301)
		//	w.Write([]byte("Redirecting to /setup..."))
		//}
		activityUpdator(-1)
		log.Printf("forwarding request to /register for part 2")
		w.Header().Set("Location", "/register")
		w.WriteHeader(http.StatusTemporaryRedirect)
		w.Write([]byte("Redirecting to /register..."))
	} else {
		//Actually, send these people to /register as well because it will collect people who abandoned the reg
		//process and will auto-forward those who have completed it to /app
		log.Printf("forwarding request to /register")
		w.Header().Set("Location", "/register")
		w.WriteHeader(http.StatusTemporaryRedirect)
		w.Write([]byte("Redirecting to /register..."))
	}
}

// crowdRiseSignupHandler is invoked in the reverse proxy and captures important details
// that our system wants about the signup if succuessful
func crowdRiseSignupHandler(w http.ResponseWriter, r *http.Request, email string, firstname string, lastname string) {
	b, err := ioutil.ReadAll(r.Body)
	log.Printf("Inside the signup handler")
	if err != nil {
		log.Printf("issue reading signup body - %v", err)
		errJSONHandler(w, r, http.StatusInternalServerError, "internal error reading the signup body")
		return
	}
	b = append(b, []byte(fmt.Sprintf("&api_key=%s&api_secret=%s&email=%s&first_name=%s&last_name=%s", CROWDRISE_API_KEY, CROWDRISE_API_SECRET, email, firstname, lastname))...)
	log.Printf("changing body to %s", b)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
	r.ContentLength = int64(len(b))

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
		//Try again with UserID as a string
		_ = signupResponse
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
	}

	// avoid panics for out of bounds index access below
	if len(signupResponse.Result) == 0 {
		log.Printf("error - crowdrise did not return data in result key - %s", string(data))
		errJSONHandler(w, r, http.StatusInternalServerError, "crowdrise did not return data in the result key")
		return
	}

	//If the user already exists, that's fine, we want to store the user's info anyway
	if !signupResponse.Result[0].UserCreated && signupResponse.Result[0].ErrorID != "1100" {
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

	_, err = DB.Exec("update users set crowdrise_username=?, crowdrise_id=?, firstname=?, lastname=? where oauth_token=? limit 1", signupResponse.Result[0].Username, signupResponse.Result[0].UserID, firstname, lastname, passedInToken)
	if err != nil {
		log.Printf("error updating user record with crowdrise information - %q", err.Error())
		errJSONHandler(w, r, http.StatusInternalServerError, "internal storage error saving crowdrise information")
		return
	}

	// pass the data back to the front end
	w.Write(data)
}

// crowdRiseNewEventHandler is invoked in the reverse proxy and captures important details
// that our system wants about the signup if succuessful
func crowdRiseNewEventTeamHandler(w http.ResponseWriter, r *http.Request, firstname string, lastname string, crowdriseUsername string, ein string) {
	//Check to make sure the user doesn't already have a team
	authParts := strings.Split(r.Header.Get("Authorization"), " ")
	if len(authParts) != 2 {
		errJSONHandler(w, r, http.StatusBadRequest, "unable to get authorization header bearer token")
		return
	}
	passedInToken := authParts[1]

	var crowdRiseTeamName sql.NullString
	err := DB.QueryRow("select crowdrise_team_id from users where oauth_token=? limit 1", passedInToken).Scan(&crowdRiseTeamName)
	if err != nil {
		if err == sql.ErrNoRows {
			errJSONHandler(w, r, http.StatusBadRequest, "invalid token, no associated user found")
			return
		}
		log.Println("error with database validating token for reverse proxy")
		errJSONHandler(w, r, http.StatusBadRequest, "internal database error")
		return
	}

	if crowdRiseTeamName.String != "" {
		log.Println("the user already has a crowdrise team")
		errJSONHandler(w, r, http.StatusBadRequest, "the user already has a crowdrise team")
		return
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("issue reading signup body - %v", err)
		errJSONHandler(w, r, http.StatusInternalServerError, "internal error reading the signup body")
		return
	}
	teamName := "300 Days of Run - " + firstname + " " + lastname
	b = append(b, []byte(fmt.Sprintf("&api_key=%s&api_secret=%s&team_name=%s&charity_ein=%s&event_username=300DaysofRun&organizer_username=%s", CROWDRISE_API_KEY, CROWDRISE_API_SECRET, teamName, ein, crowdriseUsername))...)
	log.Printf("changing body to %s", b)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
	r.ContentLength = int64(len(b))

	resp, err := http.Post(CROWDRISE_BASE_URL+"/api/create_event_team", "application/x-www-form-urlencoded", bytes.NewBuffer(b))
	log.Printf("Postd request. Response: %v", resp)
	if err != nil {
		log.Printf("error adding user to event - %q", err.Error())
		errJSONHandler(w, r, http.StatusInternalServerError, "error adding user to event")
		return
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error reading response body from event add request - %q", err.Error())
		errJSONHandler(w, r, http.StatusInternalServerError, "error reading response from crowdrise")
		return
	}

	if resp.StatusCode > 300 {
		log.Printf("unexpected response from crowdrise event add: %s", data)
		errJSONHandler(w, r, http.StatusInternalServerError, "unexpected result from crowdrise")
		return
	}

	var createTeamResponse struct {
		Status string `json:"status"`
		Result []struct {
			TeamCreated  bool   `json:"team_created"`
			URL          string `json:"url"`
			PrivateURL   string `json:"private_url"`
			TeamUsername string `json:"team_username"`
			TeamID       int    `json:"team_id"`
			ErrorID      int    `json:"error_id"`
			Error        string `json:"error"`
		} `json:"result"`
	}
	var createTeamErrorResponse struct {
		Status string `json:"status"`
		Result []struct {
			TeamCreated bool   `json:"team_created"`
			ErrorID     string `json:"error_id"`
			Error       string `json:"error"`
		} `json:"result"`
	}
	err = json.Unmarshal(data, &createTeamResponse)
	if err != nil {
		err = json.Unmarshal(data, &createTeamErrorResponse)
		if err != nil {
			log.Printf("error unmarshalling create team response for %q: %q", string(data), err.Error())
			errJSONHandler(w, r, http.StatusInternalServerError, "unable to parse result from crowdrise create team ")
			return
		}
		//Something went wrong, the team was not created and doesn't already exist
		w.Write(data)
		return
	}

	// avoid panics for out of bounds index access below
	if len(createTeamResponse.Result) == 0 {
		log.Printf("error - crowdrise did not return data in result key - %s", string(data))
		errJSONHandler(w, r, http.StatusInternalServerError, "crowdrise did not return data in the result key")
		return
	}

	//If the user already exists, that's fine, we want to store the user's info anyway
	if !createTeamResponse.Result[0].TeamCreated {
		log.Printf("error - team not created - %s", string(data))
		errJSONHandler(w, r, http.StatusInternalServerError, fmt.Sprintf("crowdrise did not create the team - %s", createTeamResponse.Result[0].Error))
		return
	}

	_, err = DB.Exec("update users set crowdrise_team_username=?, crowdrise_team_id=?, crowdrise_private_url=?, crowdrise_public_url=? where oauth_token=? limit 1", createTeamResponse.Result[0].TeamUsername, createTeamResponse.Result[0].TeamID, createTeamResponse.Result[0].PrivateURL, createTeamResponse.Result[0].URL, passedInToken)
	if err != nil {
		log.Printf("error updating user record with crowdrise team information - %q", err.Error())
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

	var email, firstname, lastname, crowdriseUsername sql.NullString
	err := DB.QueryRow("select email, firstname, lastname, crowdrise_username from users where oauth_token=? limit 1", passedInToken).Scan(&email, &firstname, &lastname, &crowdriseUsername)
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
		crowdRiseSignupHandler(w, r, email.String, firstname.String, lastname.String)
		return
	case "api/url_data":
	case "api/create_event_team":
		crowdRiseNewEventTeamHandler(w, r, firstname.String, lastname.String, crowdriseUsername.String, r.URL.Query().Get("ein"))
		return
	case "api/charity_basic_search":
		values := r.URL.Query()
		values.Add("api_key", CROWDRISE_API_KEY)
		values.Add("api_secret", CROWDRISE_API_SECRET)
		r.URL.RawQuery = values.Encode()
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
	log.Printf("request URL is: %s", r.URL)
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

// runnerProfileHandler responds to /runners/99999 where 99999 is a user ID. It presents
// the profile.html template.
func runnerProfileHandler(w http.ResponseWriter, r *http.Request) {
	templates := []string{"templates/base.html", "templates/profile.html"}
	userID, ok := mux.Vars(r)["rest"]
	customMessage := html.EscapeString(strings.TrimSpace(r.URL.Query().Get("message")))
	if !ok {
		errJSONHandler(w, r, http.StatusBadRequest, "missing user ID")
		return
	}
	t, err := template.ParseFiles(templates...)
	if err != nil {
		log.Println("unable to parse profile.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing profile template")
		return
	}
	userIDInt, _ := strconv.Atoi(userID)
	var stravaID, crowdRisePublicURL, firstname, lastname, crowdriseTeamID, daysrun sql.NullString
	var metersrun, metersgained sql.NullFloat64
	log.Println("User ID from URL: ", userID)
	err = DB.QueryRow("select users.strava_id, firstname, lastname, crowdrise_public_url, crowdrise_team_id, count(distinct date(activities.start_date)) as daysrun, sum(ifnull(Distance,0.0)) as metersrun, sum(ifnull(Elevation,0.0)) as metersgained from users left join activities on users.id = activities.user_id and start_date >=? where users.strava_id=? group by users.strava_id, firstname, lastname, crowdrise_public_url, crowdrise_team_id", time.Date(2016, time.January, 1, 0, 0, 0, 0, time.UTC).Format(MysqlDateFormat), userIDInt).Scan(&stravaID, &firstname, &lastname, &crowdRisePublicURL, &crowdriseTeamID, &daysrun, &metersrun, &metersgained)
	if err != nil {
		if err == sql.ErrNoRows {
			errJSONHandler(w, r, http.StatusBadRequest, "invalid token, no associated user found")
			return
		}
		log.Println("error with database getting user ID")
		errJSONHandler(w, r, http.StatusBadRequest, "internal database error")
		return
	}

	data := struct {
		FirstName       string
		LastName        string
		PublicURL       string
		CrowdriseTeamID string
		StravaID        string
		DaysRun         string
		MilesRun        string
		FeetGained      string
		CustomMessage   string
	}{
		FirstName:       firstname.String,
		LastName:        lastname.String,
		PublicURL:       crowdRisePublicURL.String,
		CrowdriseTeamID: crowdriseTeamID.String,
		StravaID:        stravaID.String,
		DaysRun:         daysrun.String,
		MilesRun:        Comma(int64(float64(metersrun.Float64) / 1609.34)),
		FeetGained:      Comma(int64(float64(metersgained.Float64) * 3.28084)),
		CustomMessage:   customMessage,
	}

	err = t.Execute(w, data)
	if err != nil {
		log.Printf("error executing template in runnerProfileHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing profile template")
		return
	}
}

// appHandler presents the app.html template and should be behind the mwAuthenticated middleware
func appHandler(w http.ResponseWriter, r *http.Request) {
	newUserFlag := r.URL.Query().Get("new_user")
	templates := []string{"templates/base.html", "templates/app.html"}
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

	var crowdRisePrivateURL, crowdRisePublicURL, firstname, crowdriseTeamID, stravaID sql.NullString
	err = DB.QueryRow("select firstname, crowdrise_private_url, crowdrise_public_url, crowdrise_team_id, strava_id from users where oauth_token=? limit 1", cookieData.AccessToken).Scan(&firstname, &crowdRisePrivateURL, &crowdRisePublicURL, &crowdriseTeamID, &stravaID)
	if err != nil {
		if err == sql.ErrNoRows {
			errJSONHandler(w, r, http.StatusBadRequest, "invalid token, no associated user found")
			return
		}
		log.Println("error with database validating token for reverse proxy")
		errJSONHandler(w, r, http.StatusBadRequest, "internal database error")
		return
	}

	//If they don't have a crowdrise team ID, send them to /register
	if crowdriseTeamID.String == "" {
		w.Header().Set("Location", "/register")
		w.WriteHeader(http.StatusTemporaryRedirect)
		w.Write([]byte("Redirecting to register..."))
	}

	var CustomMessage string
	if newUserFlag == "true" {
		CustomMessage = crowdRisePrivateURL.String
	}

	data := struct {
		Email           string
		NewUser         string
		FirstName       string
		PublicURL       string
		PrivateURL      string
		CrowdriseTeamID string
		AthleteURL      string
		CustomMessage   string
	}{
		Email:           cookieData.StravaAthlete.Email,
		NewUser:         newUserFlag,
		FirstName:       firstname.String,
		PublicURL:       crowdRisePublicURL.String,
		PrivateURL:      crowdRisePrivateURL.String,
		CrowdriseTeamID: crowdriseTeamID.String,
		AthleteURL:      "http://300daysofrun.com/runners/" + stravaID.String,
		CustomMessage:   CustomMessage,
	}

	err = t.Execute(w, data)
	if err != nil {
		log.Printf("error executing template in appHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing app template")
		return
	}
}

// setupHandler presents the setup.html template and should be behind the mwAuthenticated middleware
func setupHandler(w http.ResponseWriter, r *http.Request) {
	templates := []string{"templates/base.html", "templates/setup.html"}
	t, err := template.ParseFiles(templates...)
	if err != nil {
		log.Println("unable to parse setup.html for rendering - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error parsing setup template")
		return
	}

	cookieData, err := readAuthCookie(r)
	if err != nil {
		log.Println("error reading cookie data in setupHandler")
		authErrHandler(w, r, "unable to read cookie data in setup.html. Please log back in.")
		return
	}

	//Check to see if the user already has a crowdrise team, and if so, fowrard them to /app
	var crowdriseTeamID sql.NullString
	err = DB.QueryRow("select crowdrise_team_id from users where oauth_token=? limit 1", cookieData.AccessToken).Scan(&crowdriseTeamID)
	if crowdriseTeamID.String != "" {
		w.Header().Set("Location", "/app")
		w.WriteHeader(http.StatusTemporaryRedirect)
		w.Write([]byte("Redirecting to app..."))
	}

	data := struct {
		Email     string
		FirstName string
	}{
		Email:     cookieData.StravaAthlete.Email,
		FirstName: cookieData.StravaAthlete.FirstName,
	}

	err = t.Execute(w, data)
	if err != nil {
		log.Printf("error executing template in setupHandler - %v", err)
		errHandler(w, r, http.StatusInternalServerError, "internal error executing setup template")
		return
	}
}

// authErrHandler redirects a request to `/` and puts a message in the query for use at the index
func authErrHandler(w http.ResponseWriter, r *http.Request, msg string) {
	log.Println("forwarding un-authed request to index")

	cookie := http.Cookie{}
	cookie.Name = AuthCookieName
	cookie.Value = ""
	cookie.Domain = ".300daysofrun.com"
	cookie.MaxAge = -1 // delete now
	http.SetCookie(w, &cookie)

	w.Header().Set("Location", "/?message="+url.QueryEscape(msg))
	w.WriteHeader(http.StatusTemporaryRedirect)
	w.Write([]byte("Redirecting to index..."))
}

func logOutHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Logging out user...")

	cookie := http.Cookie{}
	cookie.Name = AuthCookieName
	cookie.Value = ""
	cookie.Domain = ".300daysofrun.com"
	cookie.MaxAge = -1 // delete now
	http.SetCookie(w, &cookie)

	cookie = http.Cookie{}
	cookie.Name = AuthCookieName
	cookie.Value = ""
	cookie.Domain = "300daysofrun.com"
	cookie.MaxAge = -1 // delete now
	http.SetCookie(w, &cookie)

	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusTemporaryRedirect)
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
		log.Printf("error decoding cookie value when reading - %s", string(decoded))
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

// mwAuthendicated prevents non-authenticated users from proceeding.
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
			log.Printf("error decoding cookie value when authenticating - %s\n-- becomes --\n%s", cookie.Value, string(decoded))
			authErrHandler(w, r, "Unable to decode cookie data. Please sign back in.")
		}
		parts := strings.Split(string(decoded), "::hmac::")
		if len(parts) != 2 {
			log.Printf("missing parts on cookie: %s", cookie)
			authErrHandler(w, r, "Corrupt cookie data. Please sign back in.")
			return
		}
		originalJSONToken := parts[0]
		log.Printf("%+v", parts)
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

// SendWelcomeEmail sends an email through the SendGrid service
// TODO: fill this out
func SendWelcomeEmail() error {
	log.Printf("API Key: %s", SENDGRID_API_KEY)
	log.Printf("Template ID: %s", SENDGRID_TEMPLATE_ID)
	sg := sendgrid.NewSendGridClientWithApiKey(SENDGRID_API_KEY)

	message := sendgrid.NewMail()
	message.AddTo("ascruggs@gmail.com")
	message.AddToName("Adam Rosenscruggs")
	message.SetFrom("noreply@300daysofrun.com")
	message.SetFromName("300 Days of Run")
	message.SetHTML("<p>This is the custom part of the body, --name--. <a href='--link--'>Link to Crowdrise</a></p>") // will be inserted into `<%body%>` in the template
	message.SetSubject("Welcome to 300 Days of Run!")       // will be inserted into `<%subject%>` in the template

	// There appears to be an issue with SendGrid Templates and substitutions currently.
	//message.AddFilter("templates", "enable", "1")
	//message.AddFilter("templates", "template_id", SENDGRID_TEMPLATE_ID)
	//message.AddSubstitution(`--name--`, "Seth")                      // have `--name--` in the transactional template
	//message.AddSubstitution(`--link--`, "http://www.crowdrise.com/") // have `--link--` in the transactional template
	log.Printf("Got to the send  portion")
	if err := sg.Send(message); err != nil {
		return err
	}

	return nil
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
	if CROWDRISE_API_KEY == "" {
		log.Println("Warning: crowdrise-api-key empty. See -h.")
	}
	if CROWDRISE_API_SECRET == "" {
		log.Println("Warning: crowdrise-api-secret empty. See -h.")
	}
	if SENDGRID_API_KEY == "" {
		log.Println("Warning: sendgrid-api-key empty. See -h.")
	}
	if SENDGRID_TEMPLATE_ID == "" {
		log.Println("Warning: sendgrid-template-id empty. See -h.")
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

//Comma formats a number as a string with thousands separators
func Comma(v int64) string {
	sign := ""
	if v < 0 {
		sign = "-"
		v = 0 - v
	}

	parts := []string{"", "", "", "", "", "", ""}
	j := len(parts) - 1

	for v > 999 {
		parts[j] = strconv.FormatInt(v%1000, 10)
		switch len(parts[j]) {
		case 2:
			parts[j] = "0" + parts[j]
		case 1:
			parts[j] = "00" + parts[j]
		}
		v = v / 1000
		j--
	}
	parts[j] = strconv.Itoa(int(v))
	return sign + strings.Join(parts[j:], ",")
}
