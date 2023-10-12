//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate"); //* Using Google auth.
const FacebookStrategy = require("passport-facebook"); //* Using facekbook auth.

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

//* Using Express-session
app.use(
  session({
    secret: "Our little scret",
    resave: false,
    saveUninitialized: false,
  })
);

//* Using passport
app.use(passport.initialize());
app.use(passport.session());

//* Connection to the database
mongoose.connect("mongodb://127.0.0.1:27017/userDB");

// creating schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  Secret: String,
});

//* Using passportLocalMongoos

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//* As if we use mongoose encryption method
// userSchema.plugin(encrypt,{secret:secret,encryptedFields:["password"] });

//* creating model
const User = new mongoose.model("User", userSchema);

//* passportLocalMongoose
passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture,
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

//* Using passport-google-oauth20 (Placed After all the setup or Before first route.)
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

//* Using facebook auth.
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/callback",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

//* Home route
app.get("/", (req, res) => {
  res.render("home");
});

//* Auth. Google Route
app.get(
  "/auth/google/",
  passport.authenticate("google", { scope: ["profile"] })
);

//* using google auth. to redirect user after authentication
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

//* Auth. Facebook Route
app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
  
);

//* Login route
app.get("/login", (req, res) => {
  res.render("login");
});

//* signin route
app.get("/register", (req, res) => {
  res.render("register");
});

//* Secret route
app.get("/secrets", async (req, res) => {
  try {
    const foundUsers = await User.find({ Secret: { $ne: null } });
    res.render("secrets", { usersWithSecrets: foundUsers });
  } catch (err) {
    console.log(err);
    res.status(500).send("Internal Server Error ");
  }
});

//* Submit Route
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

//* Post route for Submit
app.post("/submit", async (req, res) => {
  const submittedSecret = req.body.secret;

  try {
    const foundUser = await User.findById(req.user.id);
    if (foundUser) {
      foundUser.Secret = submittedSecret;
      await foundUser.save();
      res.redirect("/secrets");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

//* Logout route
app.get("/logout", (req, res) => {
  req.logout(req.user, (err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

//* Post register
app.post("/register", (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

//* Post login route
app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

//! Server running at port 3000
app.listen(3000, function () {
  console.log("Server is running on the portn 3000");
});
