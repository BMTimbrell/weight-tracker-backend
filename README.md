#Weight Tracker Server

##About

This is a [server](https://github.com/BMTimbrell/weight-tracker-backend). I made using Node and Express for a weight tracker app. It queries a Postgres database, which is hosted on Supabase. I used Render to host the server.

## Features

* User registration and login using Passport.js for authentication
* Endpoints for fetching weight data and user information
* Endpoints for updating user information as well as weight data
* Uses node-postgres to connect to and query PostgreSQL database
* Middleware for checking if a user can perform certain requests