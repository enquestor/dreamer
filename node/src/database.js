const { GraphQLClient, gql } = require("graphql-request");
const {
  HASURA_GRAPHQL_ADMIN_SECRET,
  REFRESH_TOKEN_EXPIRATION_TIME_DAYS,
  NODE_HASURA_URL,
} = require("./config");

const client = new GraphQLClient(NODE_HASURA_URL, {
  headers: {
    "x-hasura-admin-secret": HASURA_GRAPHQL_ADMIN_SECRET,
  },
});

/**
 * Adds a user with the given parameters.
 *
 * @param {Object} user
 * @param {String} user.username - The username of the user.
 * @param {String} user.password - Hashed password with the following: SHA256((SHA256(password) + salt)).
 * @param {String} user.salt - Salt used to hash the password.
 * @param {String} user.name - The name of the user.
 * @param {String} user.email - The email of the user.
 *
 * @returns {Object} - User object with id only.
 */
async function insertUser({ username, password, salt, name, email }) {
  const mutation = gql`
    mutation {
      insert_users_one(
        object: { 
          username: "${username}", 
          password: "${password}", 
          salt: "${salt}", 
          name: "${name}", 
          email: "${email}"
        }
      ) {
        id
      }
    }
  `;

  const result = await client.request(mutation);
  const user = result.insert_users_one;

  return user;
}

/**
 * @param {Object} user
 * @param {String} user.username - The username of the user.
 *
 * @returns {Object} - User object with id, username, password, and salt properties.
 *
 * @throws {Object} - Error when user is not found.
 */
async function getUser({ username }) {
  const query = gql`
    query {
      users(where: {username: {_eq: "${username}"}}) {
        id
        username
        password
        salt
      }
    }
  `;

  const result = await client.request(query);
  if (result.users.length === 0) {
    throw { message: "User not found" };
  }

  const user = result.users[0];
  return user;
}

/**
 * Checks if the refresh token exists in the database.
 *
 * @param {Object} refreshToken
 * @param {String} refreshToken.refreshToken - The refresh token of the user.
 *
 * @throws {Object} - Error when refresh token is not found.
 */
async function checkRefreshToken({ refreshToken }) {
  const query = gql`
    query {
      refresh_tokens(where: {refresh_token: {_eq: "${refreshToken}"}}) {
        user_id
        refresh_token
      }
    }
  `;

  const result = await client.request(query);
  if (result.refresh_tokens.length === 0) {
    throw { message: "Refresh token not found" };
  }
}

/**
 * Insert a new refresh token to the database.
 *
 * @param {Object} user
 * @param {String} user.userId - The id of the user.
 * @param {String} user.refreshToken - The refresh token associated with the user.
 */
async function insertRefreshToken({ userId, refreshToken }) {
  const expiresAt = new Date(
    Date.now() + REFRESH_TOKEN_EXPIRATION_TIME_DAYS * 24 * 60 * 60 * 1000
  );
  const mutation = gql`
    mutation {
      insert_refresh_tokens_one(
        object: { 
          user_id: "${userId}", 
          refresh_token: "${refreshToken}"
          expires_at: "${expiresAt.toISOString()}"
        }
      ) {
        refresh_token
      }
    }
  `;

  await client.request(mutation);
}

/**
 * Deletes the refresh token from the database.
 *
 * @param {Object} refreshToken
 * @param {String} refreshToken.refreshToken - The refresh token of the user.
 */
async function deleteRefreshToken({ refreshToken }) {
  const mutation = gql`
    mutation {
      delete_refresh_tokens(where: {refresh_token: {_eq: "${refreshToken}"}}) {
        affected_rows
      }
    }
  `;

  await client.request(mutation);
}

module.exports = {
  insertUser,
  getUser,
  checkRefreshToken,
  insertRefreshToken,
  deleteRefreshToken,
};
