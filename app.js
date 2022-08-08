// Requiring all the packages installed through NPM
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const encrypt = require("mongoose-encryption");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");

// Initialise the express as an app
const app = express();

// Make the app use other packages and features
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine", "ejs");

// Init session and passport
app.use(session({
    secret: "Tis the secret",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.authenticate('session'));

//Connecting to the Database
main().catch((err) => console.log(err));
async function main() {
    await mongoose.connect("mongodb://localhost:27017/userDB");
}

//Schema for oue database on MongoDB
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

// Associating outside functions to the schema object
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Creating a new model with the userSchema
const User = new mongoose.model("User", userSchema);

// Strategy for local username/password sign-up
passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        cb(null, { id: user.id, username: user.username, name: user.name });
    });
});
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});

// Google Strategy setup and configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Facebook Strategy setup and configuration
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// GETs and POSTs routes
app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets", passport.authenticate("google", { 
    failureRedirect: "/login",
    successRedirect: "/secrets"
}));

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get("/auth/facebook/secrets", passport.authenticate("facebook", { 
    failureRedirect: "/login",
    successRedirect: "/secrets"
}));

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    User.find({"secret": {$ne: null}}, (err, foundUsers) => {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", (req, res) => {

    const submittedSecret = req.body.secret;

    User.findById(req.user.id, (err, foundUser) => {
        if (err) {
            console.log(err);
        } else {
            foundUser.secret = submittedSecret;
            foundUser.save();
            res.redirect("/secrets");
        }
    });
});

app.get("/logout", function(req, res, next) {
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect("/");
    });
});

app.post("/register", (req, res) => {

    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if(err) {
            console.log("Registration error: " + err);
            res.redirect("/register");
        }

        const authenticate = User.authenticate();
        authenticate(req.body.username, req.body.password, (err, result) => {
            if (err) {
                console.log("Authentication error: " + err);
            } else {
                res.redirect("/secrets");
            }
        });
    });
});

app.post("/login", 
  passport.authenticate("local", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
});

// TODO: Listing on default port for now, change when deployed
app.listen(3000, (err) => {
    if (!err) {
        console.log("Seccessfully listening on port 3000.");
    }
});