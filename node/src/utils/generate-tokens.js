const {
  HASURA_GRAPHQL_JWT_KEY,
  TOKEN_EXPIRATION_TIME_MINUTES,
  REFRESH_TOKEN_EXPIRATION_TIME_DAYS,
} = require("../config");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

function generateTokens(userId) {
  const token = jwt.sign(
    {
      "https://hasura.io/jwt/claims": {
        "x-hasura-allowed-roles": ["user"],
        "x-hasura-default-role": "user",
        "x-hasura-user-id": userId,
      },
    },
    HASURA_GRAPHQL_JWT_KEY,
    { expiresIn: `${TOKEN_EXPIRATION_TIME_MINUTES}m` }
  );
  const refreshToken = jwt.sign(
    { userId, salt: crypto.randomBytes(16).toString("hex") },
    HASURA_GRAPHQL_JWT_KEY,
    { expiresIn: `${REFRESH_TOKEN_EXPIRATION_TIME_DAYS}d` }
  );
  return { token, refreshToken };
}

module.exports = generateTokens;
