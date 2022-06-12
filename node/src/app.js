const express = require("express");
const crypto = require("crypto");
const sha256 = require("crypto-js/sha256");
const {
  HASURA_GRAPHQL_JWT_KEY,
  REFRESH_TOKEN_EXPIRATION_TIME_DAYS,
} = require("./config");
const generateTokens = require("./utils/generate-tokens");
const jwt = require("jsonwebtoken");
const database = require("./database");
const cookieParser = require("cookie-parser");

const refreshTokenCookieProperties = {
  httpOnly: true,
  secure: false,
  sameSite: "strict",
  overwrite: true,
  maxAge: REFRESH_TOKEN_EXPIRATION_TIME_DAYS * 24 * 60 * 60 * 1000,
};

const app = express();
app.use(express.json());
app.use(cookieParser());

app.get("/", (_, res) => {
  res.send("Express Server");
});

app.post("/signup", async (req, res) => {
  console.log("/signup");

  // validate request
  const { body } = req;
  if (
    !(
      body.hasOwnProperty("username") &&
      body.hasOwnProperty("password") &&
      body.hasOwnProperty("name") &&
      body.hasOwnProperty("email")
    )
  ) {
    res.status(400).send({ error: "Invalid request" });
    return;
  }
  const { username, password, name, email } = body;

  // generate salt and hashed password
  const salt = crypto.randomBytes(16).toString("hex");
  const hashedPassword = sha256(password + salt).toString();

  try {
    // add user to database
    const user = await database.insertUser({
      username,
      password: hashedPassword,
      salt,
      name,
      email,
    });

    // generate tokens and add refresh token to database
    const { token, refreshToken } = generateTokens(user.id);
    await database.insertRefreshToken({ userId: user.id, refreshToken });

    res.cookie("refreshToken", refreshToken, refreshTokenCookieProperties);
    res.send({ token });
  } catch (error) {
    res.status(400).send({ error: error.message });
  }
});

app.post("/login", async (req, res) => {
  console.log("/login");

  // validate request
  const { body } = req;
  if (!(body.hasOwnProperty("username") && body.hasOwnProperty("password"))) {
    res.status(400).send({ error: "Invalid request" });
    return;
  }
  const { username, password } = body;

  try {
    // get user from database
    const user = await database.getUser({ username });

    // check hashed password
    const hashedPassword = sha256(password + user.salt).toString();
    if (user.password !== hashedPassword) {
      res.status(401).send({ error: "Invalid username or password" });
      return;
    }

    // generate tokens and add refresh token to database
    const { token, refreshToken } = generateTokens(user.id);
    await database.insertRefreshToken({ userId: user.id, refreshToken });

    res.cookie("refreshToken", refreshToken, refreshTokenCookieProperties);
    res.send({ token });
  } catch (error) {
    res.status(400).send({ error: error.message });
    return;
  }
});

app.post("/refresh", async (req, res) => {
  console.log("/refresh");

  // validate request
  const cookies = Object.assign({}, req.cookies);
  if (!cookies.hasOwnProperty("refreshToken")) {
    res.status(400).send({ error: "Invalid request" });
    return;
  }
  const { refreshToken } = cookies;

  try {
    // decode token
    const { userId } = jwt.verify(refreshToken, HASURA_GRAPHQL_JWT_KEY);

    // check if refresh token exists and delete it
    await database.checkRefreshToken({ refreshToken });
    await database.deleteRefreshToken({ refreshToken });

    // generate new tokens and add refresh token to database
    const { token, refreshToken: newRefreshToken } = generateTokens(userId);
    await database.insertRefreshToken({
      userId,
      refreshToken: newRefreshToken,
    });

    res.cookie("refreshToken", newRefreshToken, refreshTokenCookieProperties);
    res.send({ token });
  } catch (error) {
    res.status(400).send({ error: error.message });
    return;
  }
});

app.post("/logout", async (req, res) => {
  console.log("/logout");

  // validate request
  const cookies = Object.assign({}, req.cookies);
  if (!cookies.hasOwnProperty("refreshToken")) {
    res.status(400).send({ error: "Invalid request" });
    return;
  }
  const { refreshToken } = cookies;

  try {
    // delete refresh token
    await database.deleteRefreshToken({ refreshToken });
  } catch (error) {
    res.status(400).send({ error: error.message });
    return;
  }
  res.clearCookie("refreshToken");
  res.send({});
});

module.exports = app;
