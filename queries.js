const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
require("dotenv").config();

const Pool = require('pg').Pool;
const pool = new Pool({
    connectionString: process.env.CONNECTION_STRING
});

const checkUserAuthorised = (req, res, next) => {
    const id = parseInt(req.params.id);
    if (parseInt(req?.user?.id) === id) next();
    else return res.status(401).json({error: 'You must be logged in as this user to access this resource'});
};

const getUserById = async (req, res) => {
    const id = parseInt(req.params.id);

    try {
        const result = await pool.query('SELECT id, name, email FROM users WHERE id = $1', [id]);
        const user = await result.rows[0];
        return res.status(200).json({
            id: user.id,
            name: user.name,
            email: user.email
        });
    } catch (error) {
        return res.status(500).json({error});
    }
};

const checkEmailExists = async (req, res, next) => {
    const { email } = req.body;

    try {
        const isRegistered = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
        if (isRegistered.rows.length) 
            return res.status(409).json({message: 'user already registered with this email'});
        next();
    } catch (error) {
        return res.status(500).json({error});
    }
};

const createUser = async (req, res) => {
    const { email, name, password } = req.body;

    if (!name || !email || !password) 
        return response.status(400).json({error: 'Invalid data'});

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = await pool.query('INSERT INTO users (email, name, password) VALUES ($1, $2, $3) RETURNING *', 
        [email, name, hashedPassword]);

        req.login(user.rows[0], function(error) {
            if (error) return res.status(500).json({message: error.message}); 
            return res.redirect(303, '/users/' + req.user.id);
        });
    } catch (error) {
        return res.status(500).json({error});
    }
};

const updateUser = async (request, response) => {
    const id = parseInt(request.params.id);
    const { email, password, name } = request.body;

    //Update email
    if (email) { 
        try {
            await pool.query(
                'UPDATE users SET email = $1 WHERE id = $2', [email, id]
            );

        } catch (error) {
            if (error) return response.status(500).error;
        }
    }

    //Update password
    if (password) {
        try {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
    
            await pool.query(
                'UPDATE users SET password = $1 WHERE id = $2', 
                [hashedPassword, id]
            );
    
        } catch (error) {
            console.log(error);
           return response.status(500).json({message: error.message}); 
        } 
    }

    if (name) {
        try {
            await pool.query(
                'UPDATE users SET name = $1 WHERE id = $2', 
                [name, id]
            );
    
        } catch (error) {
            console.log(error);
           return response.status(500).json({message: error.message}); 
        } 
    }

    return response.status(200).json({message: 'Update Complete!'});
};

//Logging in
passport.use(new LocalStrategy({ usernameField: 'email' }, function verify(email, password, done) {
    pool.query('SELECT * FROM users WHERE email = $1', [email], async (error, user) => {
        if (error) return done(error);
        if (!user.rows) {
            return done(new Error('User doesn\'t exist!'));
        }

        //Check passwords match
        try {
            const matchedPassword = await bcrypt.compare(password, user.rows[0].password);
            if (!matchedPassword) return done(new Error('Incorrect password!'));
            return done(null, user.rows[0]);
        } catch (error) {
            return done(error);
        }
        
    });
}));

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    pool.query('SELECT * FROM users WHERE id = $1', [id], (error, results) => {
        if (error) return done(error);
        return done(null, results.rows[0]);
    });
});

const getWeight = async (req, res) => {
    const id = parseInt(req.params.id);

    try {
        const weight = await pool.query('SELECT * FROM weights WHERE user_id = $1 ORDER BY date', [id]);
        return res.status(200).json({weightList: weight.rows});
    } catch (error) {
        return res.status(500).json({error});
    }
};

const addWeight = async (req, res) => {
    const id = parseInt(req.params.id);
    const { weight, date } = req.body;

    try {
        const addedWeight = await pool.query('INSERT INTO weights (user_id, weight, date) VALUES ($1, $2, $3) RETURNING weight, date', [id, weight, date]);
        return res.status(201).json({weight: addedWeight.rows[0].weight, date: addedWeight.rows[0].date});
    } catch (error) {
        return res.status(500).json({error});
    }
};

const updateWeight = async (req, res) => {
    const id = parseInt(req.params.dataId);
    const { weight, date } = req.body;

    try {
        const updatedWeight = await pool.query('UPDATE weights SET weight = $1, date = $2 WHERE id = $3 RETURNING weight, date', [weight, date, id]);
        return res.status(200).json({weight: updatedWeight.rows[0].weight, date: updatedWeight.rows[0].date});
    } catch (error) {
        return res.status(500).json({error});
    }
};

const deleteWeight = async (req, res) => {
    const id = parseInt(req.params.dataId);

    try {
        await pool.query('DELETE FROM weights WHERE id = $1', [id]);
        return res.status(200).json({message: 'Deletion successful'});
    } catch (error) {
        return res.status(500).json({error});
    }
};

module.exports = {
    checkUserAuthorised,
    getUserById,
    checkEmailExists,
    createUser,
    updateUser,
    getWeight,
    addWeight,
    updateWeight,
    deleteWeight
};