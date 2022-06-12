const { HASURA_GRAPHQL_JWT_KEY } = require("../src/config");
const generateTokens = require("../src/utils/generate-tokens");
const jwt = require("jsonwebtoken");

describe("generateTokens: Generates an object with one token and one refreshToken", () => {
  test("Valid tokens for given userId", () => {
    const { token, refreshToken } = generateTokens("myTestUserId");
    jwt.verify(token, HASURA_GRAPHQL_JWT_KEY);
    jwt.verify(refreshToken, HASURA_GRAPHQL_JWT_KEY);
  });
});
