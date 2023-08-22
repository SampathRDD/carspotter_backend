require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("./model/user");
const auth = require("./middleware/auth");

const app = express();

app.use(express.json({ limit: "50mb" }));

app.post("/register", async (req, res) => {
  try {
    // Get user input
    const { first_name, last_name, email, password } = req.body;

    // Validate user input
    if (!(email && password && first_name && last_name)) {
      return res.status(400).json({
        status: "failure",
        message: "All input is required",
        data: null,
      });
    }

    // check if user already exists
    // Validate if user exists in our database
    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(409).json({
        status: "failure",
        message: "User Already Exist. Please Login",
        data: null,
      });
    }

    // Encrypt user password
    const encryptedPassword = await bcrypt.hash(password, 10);

    // Create user in our database
    const user = await User.create({
      first_name,
      last_name,
      email: email.toLowerCase(), // sanitize: convert email to lowercase
      password: encryptedPassword,
    });

    // Create token
    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY,
      {
        expiresIn: "2h",
      }
    );
    // Save user token
    user.token = token;

    // Return new user
    return res.status(201).json({
      status: "success",
      data: user,
      message: "",
    });
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  try {
    // Get user input
    const { email, password } = req.body;

    // Validate user input
    if (!(email && password)) {
      return res.status(400).json({
        status: "failure",
        message: "All input is required",
        data: null,
      });
    }
    // Validate if user exists in our database
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );

      // Save user token
      user.token = token;

      // Return user
      return res.status(200).json({
        status: "success",
        data: user,
        token: token,
        message: "",
      });
    }
    return res.status(400).json({
      status: "failed",
      message: "Invalid Credentials",
      data: null,
    });
  } catch (err) {
    console.log(err);
  }
});

app.get("/welcome", auth, (req, res) => {
  res.status(200).json({
    status: "success",
    data: null,
    message: "Welcome 🙌",
  });
});

app.use("*", (req, res) => {
  res.status(404).json({
    status: "failure",
    message: "Page not found",
    data: null,
  });
});

module.exports = app;
