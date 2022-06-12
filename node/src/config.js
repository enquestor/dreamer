const dotenv = require("dotenv");

dotenv.config();

const config = {
  HASURA_GRAPHQL_ADMIN_SECRET: process.env.HASURA_GRAPHQL_ADMIN_SECRET,
  HASURA_GRAPHQL_JWT_KEY: JSON.parse(process.env.HASURA_GRAPHQL_JWT_SECRET)[
    "key"
  ],
  NODE_HASURA_URL:
    process.env.NODE_HASURA_URL ?? "http://hasura:8080/v1/graphql",
  NODE_PORT: process.env.NODE_PORT ?? 3000,
  TOKEN_EXPIRATION_TIME_MINUTES: 15,
  REFRESH_TOKEN_EXPIRATION_TIME_DAYS: 7,
};

console.log("[config]:", config);

module.exports = config;
