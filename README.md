# Run4Charity

Backend server for Strava integration that ties in with charities.

## Running locally

You can run the server using environment variables or use flags.

Environment Variables:
Create a `.env` file, update the config values, and source the file.
```bash
$ cp example.env production.env
$ vim production.env # change the values
$ . production.env
$ go run server.go
```

Flags:
To see a listing of all flags that can be used, use `-h`.
```bash
$ go run server.go -h
```

## Endpoints
```
    # root, provides the login with strava ability
    /

    # strava domain callback url, used for logging in with strava
    /token_exchange

    # this is where users interact with the service
    # they should see a summary of their activities and
    # be able to interact with charities
    /app

    # provides data on days ran, to be used in /app
    # optional parameter: -d '{"start_date":"2015-11-25"}'
    # otherwise defaults to the config EARLIEST_POLL_UNIX
    /user/{strava_id}/summary -H 'Authentication: Bearer 100000000a'
```

## Program Flow

The index page `/` provides a link to log in via your Strava account. This takes the user to Strava to authenticate. A callback URL returns the user where the Strava data is authenticated against. The Strava data is stored as a cookie (`auth_cookie`), the user is either created or updated, the user's activities are polled, and the user is forwarded to the main application page `/app`.

Meanwhile, a background job periodically queries for updates to user activities on a schedule set by config.

## Security
The `auth_cookie` is stored locally on the end-user's side and is signed via HMAC. If the data is tampered, then the HMAC signature is invalidated and the auth_cookie will no longer validate. The user must sign back in.

## Javascript access to data
Read in the `auth_cookie`, base64 decode it, split on `::hmac::`. The first part will be the json string representing the currently logged in user. The `access_token` can be used in any endpoint for this service needing an authentication bearer token. Additionally, the `athlete.id` is the id to refer to when making calls on behalf of the user to this service.

## Database
```
CREATE TABLE `users` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `strava_id` int(11) unsigned NOT NULL,
  `email` varchar(255) NOT NULL,
  `oauth_token` varchar(255) NOT NULL,
  `last_activity_update` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `strava_id_2` (`strava_id`),
  KEY `strava_id` (`strava_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

CREATE TABLE `activities` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(11) unsigned NOT NULL,
  `strava_id` int(11) NOT NULL,
  `distance` float DEFAULT '0',
  `start_date` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `strava_id` (`strava_id`),
  UNIQUE (`strava_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;
```

## TODO:
 - Create endpoint for getting days run via local db based on strava data
 - Figure out charity API
 - Log to the database relevant metrics (page requests?, user login count?)
