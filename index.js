// server.js
require("./passport");
require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const authModel = require("./Models/Model");
const bcrypt = require("bcrypt");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");
const TodoRoutes = require("./Routes/TodoRoutes");
const NoteRoutes = require("./Routes/NoteRoutes");
const TaskRoutes = require("./Routes/TaskRoutes");
const mongoose = require("mongoose");

const PORT = process.env.PORT || 5032;

const app = express();

// CORS, JSON and URL Encoded middleware
app.use([
  cors({
    // origin: [
    //   "http://localhost:3000",
    //   "https://task-management-frontend-bice.vercel.app",
    //   process.env.FRONTEND_DOMAIN,
    // ],
    origin: [process.env.FRONTEND_DOMAIN, "http://localhost:3000"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
  express.json(),
  express.urlencoded({ extended: true }),
]);

// Session store configuration
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGO_URL,
  collectionName: "session",
});

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    store: sessionStore,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Root route
app.get("/", (req, res) => {
  res.json("hello");
});

// ---------------------
// Registration Endpoint
// ---------------------
app.post("/register", async (req, res) => {
  const { userName, email, password } = req.body;
  try {
    // Check if user already exists
    const user = await authModel.findOne({ email: email });
    if (user) {
      return res.json("Already Registerd");
    }
    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    // Create and save the new user
    const newAuth = new authModel({
      userName,
      email,
      password: hashedPassword,
    });
    const savedUser = await newAuth.save();
    res.send(savedUser);
  } catch (err) {
    res.status(400).send(err);
  }
});

// -------------------------
// Google and Facebook Auth
// -------------------------

// Google Authentication using Passport
app.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: process.env.FRONTEND_DOMAIN,
    successRedirect: `${process.env.FRONTEND_DOMAIN}/Home`,
  })
);

// Facebook Authentication using Passport
app.get("/facebook", passport.authenticate("facebook", { scope: ["email"] }));

app.get(
  "/facebook/callback",
  passport.authenticate("facebook", {
    failureRedirect: process.env.FRONTEND_DOMAIN,
    successRedirect: `${process.env.FRONTEND_DOMAIN}/Home`,
  })
);

// -------------------------
// Local Login with JWT
// -------------------------
app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: process.env.FRONTEND_DOMAIN,
  }),
  (req, res) => {
    // req.user is set by Passport after successful login.
    const payload = {
      id: req.user._id,
      email: req.user.email,
    };

    jwt.sign(
      payload,
      process.env.JWT_SECRET_KEY,
      { expiresIn: "1h" },
      (err, token) => {
        if (err) {
          console.error("JWT sign error:", err);
          return res.status(500).json({ error: "Error generating token" });
        }
        res.header(
          "Access-Control-Allow-Origin",
          process.env.FRONTEND_DOMAIN || "http://localhost:3000"
        );
        // Send the token along with a success message
        res.json({ success: true, token, message: "Successfully logged in" });
      }
    );
  }
);

// Logout endpoint (if you still use session logout)
app.get("/logout", (req, res, next) => {
  req.logOut((err) => {
    if (err) res.send(err);
    else res.json({ success: "logged out" });
  });
});

// Get current user (session-based)
app.get("/getUser", (req, res, next) => {
  if (req.user) {
    res.json(req.user);
  }
});

// -------------------------
// Forgot & Reset Password
// -------------------------
app.post("/resetPassword/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  const { newPassword } = req.body;
  jwt.verify(token, process.env.JWT_SECRET_KEY, async (err, decoded) => {
    if (err) return res.send({ Status: "Try again after few minutes" });
    try {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);
      await authModel.findByIdAndUpdate(id, { password: hashedPassword });
      res.send({ Status: "success" });
    } catch (error) {
      res.send({ Status: error });
    }
  });
});

app.post("/forgotpass", async (req, res) => {
  const { email } = req.body;
  const user = await authModel.findOne({ email: email });
  if (!user) return res.send({ Status: "Enter a valid email" });
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, {
    expiresIn: "1d",
  });
  var transporter = nodemailer.createTransport({
    service: "gmail",
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: "jhonmoorthi85131@gmail.com",
      pass: "klxb xvje ygnr qvbo", // Consider using environment variables for sensitive info
    },
  });

  var mailOptions = {
    from: "jhonmoorthi85131@gmail.com",
    to: email,
    subject: "Forgot password for task manager",
    text: `${process.env.FRONTEND_DOMAIN}/ResetPass/${user._id}/${token}`,
  };

  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      return res.send({ Status: "success" });
    }
  });
});

// -------------------------
// JWT Authenticator Middleware
// -------------------------
const jwtAuthenticator = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res
      .status(401)
      .json({ error: "No token provided, authorization denied" });
  const token = authHeader.split(" ")[1];
  if (!token)
    return res
      .status(401)
      .json({ error: "Token missing, authorization denied" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = decoded; // Optionally attach the decoded payload to req.user
    next();
  } catch (error) {
    return res.status(401).json({ error: "Token is not valid" });
  }
};

// -------------------------
// Protected Routes using JWT
// -------------------------
// app.use("/todo", TodoRoutes);
// app.use("/note", NoteRoutes);
// app.use("/task", TaskRoutes);
app.use("/todo", jwtAuthenticator, TodoRoutes);
app.use("/note", jwtAuthenticator, NoteRoutes);
app.use("/task", jwtAuthenticator, TaskRoutes);

mongoose
  .connect(process.env.MONGO_URL)
  .then(() => {
    console.log("App connected to database ✅");

    app.listen(PORT, () => {
      console.log(`App is listening to port: ${PORT} ✈️`);
    });
  })
  .catch((err) => {
    console.log(err);
  });

module.exports = app;
