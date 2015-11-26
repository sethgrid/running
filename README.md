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

## Program Flow

The index page `/` provides a link to log in via your Strava account. This takes the user to Strava to authenticate. A callback URL returns the user where the Strava data is authenticated against. The Strava data is stored as a cookie (`auth_cookie`), the user is either created or updated, the user's activities are polled, and the user is forwarded to the main application page `/app`.

Meanwhile, a background job periodically queries for updates to user activities on a schedule set by config.

## Security
The `auth_cookie` is stored locally on the end-user's side and is signed via HMAC. If the data is tampered, then the HMAC signature is invalidated and the auth_cookie will no longer validate. The user must sign back in.

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
  `strava_id` int(11) NOT NULL,
  `distance` float DEFAULT '0',
  `start_date` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `strava_id_2` (`strava_id`),
  KEY `strava_id` (`strava_id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8;
```

## TODO:
 - Grab running data on behalf of the user
 - Design initial DB schema
 - Log to database created at, email address
 - Log to the database relevant running data
 - Log to the database relevant metrics (last login)
 - Figure out charity API
