const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const cors = require('cors');
const port = process.env.PORT || 3001;
const passport = require('passport');
const session = require('express-session');
const db = require('./queries');

//app.enable('trust proxy');

app.use(
    session({
        secret: 'asdawac21',
        cookie: { 
            maxAge: 300000000,
            sameSite: true,
            secure: false
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
    (req, res) => {
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.redirect(303, "../users/" + req.user.id);
    }
);
app.get('/login', (req, res) => {
    res.status(401).json({ message: 'login failed' });
});
app.get('/logout', (req, res, next) => {
    req.logout((error) => {
        if (error) return next(error);
        res.status(200).json({message: 'logout successful'});
    });
});

app.get('/users/:id/weight', db.checkUserAuthorised, db.getWeight);
app.post('/users/:id/weight', db.checkUserAuthorised, db.addWeight);