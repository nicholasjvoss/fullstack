const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { secretOrKey } = require('../../config/keys');
const passport = require('passport');

// Load User model
const User = require('../../models/User');

// @route   GET api/users/test
// @desc    Tests users route
// @access  Public
router.get('/test', (req, res) => res.json({ msg: 'Users works!' }));

// @route   GET api/users/register
// @desc    Register a user
// @access  Public
router.post('/register', (req, res) => {
    User.findOne({ email: req.body.email })
        .then(user => {
            if(user) {
                const emailExistsMsg = `The email, ${ req.body.email }, already exists!`;
                return res.status(400).json({ email: emailExistsMsg });
            } else {
                const avatar = gravatar.url(req.body.email, {
                    s: '200',   // size
                    r: 'pg',    // rating
                    d: 'mm',    // default
                });

                const newUser = new User({
                    name: req.body.name,
                    email: req.body.email,
                    password: req.body.password,
                    avatar
                });

                // bcrypt salt...
                bcrypt.genSalt(10, (err, salt) => {
                    // ...then hash
                    bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if(err) throw err;
                        // If hashing successful, save to DB
                        newUser.password = hash;
                        newUser.save()
                            .then(user => res.json(user))
                            .catch(err => console.log(err));
                    })
                })
            }
        })
})

// @route   GET api/users/login
// @desc    Login User / Returning JWT token
// @access  Public
router.post('/login', (req, res) => {
    // const { body: { email, password } } = req;
    const email = req.body.email;
    const password = req.body.password;

    // Find user by email
    User.findOne({ email }).then(user => {
        if(!user) {
            return res.status(404).json({ email: 'User not found!' });
        }

        // Check password
        bcrypt.compare(password, user.password).then(isMatch => { // compare(request.body.password, hashed password)
            if(isMatch) {
                // User matched. Create JWT payload...
                const payload = {
                    id: user.id,
                    name: user.name,
                    avatar: user.avatar
                };

                // Sign token
                jwt.sign(
                    payload,
                    secretOrKey,
                    { expiresIn: 3600 },
                    (err, token) => {
                        // Send token as response
                        res.json({
                            success: true,
                            token: `Bearer ${ token }`
                        })
                    }
                );
            } else {
                return res.status(400).json({ password: 'Password incorrect!' });
            }
        })
    })
});

// @route   GET api/users/current
// @desc    Returns current user
// @access  Private
router.get(
    '/current',
    passport.authenticate('jwt', { session: false }),
    (req, res) => {
        res.json({
            id: req.user.id,
            name: req.user.name,
            email: req.user.email,
        });
    }
);

module.exports = router;