const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const cors = require('cors');
const port = process.env.PORT || 3001;
const passport = require('passport');
const session = require('express-session');
const db = require('./queries');

app.enable('trust proxy');

app.use(
    session({
        secret: 'asdawac21',
        cookie: { 
            maxAge: 300000000,
            sameSite: 'none',
            secure: true
        },
        resave: true,
        saveUninitialized: true
    })
);

app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(bodyParser.json());
app.use(
    bodyParser.urlencoded({
        extended: true
    })
);

app.get('/', (req, res) => {
    res.json({ info: 'Node.js, Express, and Postgres API' });

});

app.listen(port, () => {
    console.log(`App running on port ${port}.`);
});

app.get('/users/:id', db.checkUserAuthorised, db.getUserById);
app.post('/register', db.checkEmailExists, db.createUser);
app.post('/login', passport.authenticate('local', {failureRedirect: '/login', failureMessage: true}), 
    (request, response) => {
        console.log('Welcome back, ' + request.user.name);
        response.setHeader('Access-Control-Allow-Credentials', 'true');
        response.redirect(303, "../users/" + request.user.id);
    }
);
app.get('/login', (request, response) => {
    response.status(401).json({ message: 'login failed' });
});
app.delete('/logout', (request, response, next) => {
    request.logout((error) => {
        if (error) return next(error);
        response.status(200).json({message: 'logout successful'});
    });
});