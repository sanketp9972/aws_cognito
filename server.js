const express = require("express");
const AWS = require("aws-sdk");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const path = require("path");

// Load environment variables
require("dotenv").config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configure AWS
AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: "us-east-1",
});

// Configure AWS Cognito
const cognito = new AWS.CognitoIdentityServiceProvider();

// Express session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

// Passport middleware initialization
app.use(passport.initialize());
app.use(passport.session());

// Google OAuth 2.0 strategy configuration
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      // Perform actions with user profile, like saving it to the database
      // here just return the profile
      return done(null, profile);
    }
  )
);

// Serialize and deserialize user for session management
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Routes
app.post("/createUser", async (req, res) => {
  try {
    const { username, password, email } = req.body;

    const params = {
      UserPoolId: process.env.USER_POOL_ID,
      Username: username,
      TemporaryPassword: password,
      UserAttributes: [
        {
          Name: "email",
          Value: email,
        },
      ],
    };

    // Create user in Cognito
    const data = await cognito.adminCreateUser(params).promise();
    console.log("User created:", data);
    res.status(201).send("User created successfully");
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).send("Error creating user");
  }
});

app.post("/createIdentity", async (req, res) => {
  try {
    const { userId } = req.body;

    const params = {
      IdentityPoolId: process.env.IDENTITY_POOL_ID,
    };

    // Create identity in Cognito
    const data = await new AWS.CognitoIdentity().getId(params).promise();
    console.log("Identity created:", data);
    res.status(201).send("Identity created successfully");
  } catch (error) {
    console.error("Error creating identity:", error);
    res.status(500).send("Error creating identity");
  }
});

app.get("/getUserAndIdentities", async (req, res) => {
  try {
    // Get user from Cognito
    const userData = await cognito
      .adminGetUser({
        UserPoolId: process.env.USER_POOL_ID,
        Username: process.env.USERNAME,
      })
      .promise();

    // Get identities from Identity Pool
    const identityData = await new AWS.CognitoIdentity({
      apiVersion: "2014-06-30",
    })
      .listIdentities({
        IdentityPoolId: process.env.IDENTITY_POOL_ID,
        MaxResults: 10, // Maximum number of identities to return
      })
      .promise();

    console.log("User data:", userData);
    console.log("Identity data:", identityData);

    res.status(200).json({
      userData: userData,
      identityData: identityData,
    });
  } catch (error) {
    console.error("Error getting user and identities:", error);
    res.status(500).send("Error getting user and identities");
  }
});

// Google OAuth 2.0 authentication route
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // Successful authentication, redirect home.
    res.redirect("/");
  }
);

app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`Hello ${req.user.displayName}!`);
  } else {
    res.redirect("/auth/google");
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
