const request = require("supertest");
const { extractCookies } = require("../src/utils/extract-cookies");
const app = require("../src/app");
const database = require("../src/database");
const { HASURA_GRAPHQL_JWT_KEY } = require("../src/config");
const jwt = require("jsonwebtoken");

jest.mock("../src/database");

describe("Test the root path", () => {
  test("It should response the GET method", async () => {
    const response = await request(app).get("/");
    expect(response.statusCode).toBe(200);
  });
});

describe("POST /signup", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  test("Invalid request without parameters", async () => {
    const response = await request(app).post("/signup");
    expect(response.statusCode).toBe(400);
  });

  test("Invalid request with invalid parameters", async () => {
    const response = await request(app).post("/signup").send({
      username: "username",
      password: "password",
      name: null,
      email: null,
    });
    expect(response.statusCode).toBe(400);
  });

  test("Invalid request with invalid parameters", async () => {
    const response = await request(app).post("/signup").send({});
    expect(response.statusCode).toBe(400);
  });

  test("Invalid request with invalid parameters", async () => {
    const response = await request(app).post("/signup").send(null);
    expect(response.statusCode).toBe(400);
  });

  test("Duplicate username", async () => {
    database.insertUser.mockResolvedValueOnce({ id: "id" });
    const firstResponse = await request(app).post("/signup").send({
      username: "username",
      password: "password",
      name: "name",
      email: "email1",
    });
    expect(firstResponse.statusCode).toBe(200);

    database.insertUser.mockImplementationOnce(() => {
      throw { message: "Duplicate username" };
    });
    const secondResponse = await request(app).post("/signup").send({
      username: "username",
      password: "password",
      name: "name",
      email: "email2",
    });
    expect(secondResponse.statusCode).toBe(400);
  });

  test("Duplicate email", async () => {
    database.insertUser.mockResolvedValueOnce({ id: "id" });
    const firstResponse = await request(app).post("/signup").send({
      username: "username1",
      password: "password",
      name: "name",
      email: "email",
    });
    expect(firstResponse.statusCode).toBe(200);

    database.insertUser.mockImplementationOnce(() => {
      throw { message: "Duplicate username" };
    });
    const secondResponse = await request(app).post("/signup").send({
      username: "username2",
      password: "password",
      name: "name",
      email: "email",
    });
    expect(secondResponse.statusCode).toBe(400);
  });

  test("Valid request", async () => {
    database.insertUser.mockResolvedValueOnce({ id: "id" });
    database.insertRefreshToken
      .mockResolvedValueOnce(null)
      .mockImplementationOnce(() => {
        throw Error;
      });

    const response = await request(app).post("/signup").send({
      username: "username",
      password: "password",
      name: "name",
      email: "email",
    });
    expect(response.statusCode).toBe(200);
  });
});

describe("POST /login", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  test("Invalid request without parameters", async () => {
    const response = await request(app).post("/login");
    expect(response.statusCode).toBe(400);
  });

  test("Invalid request with invalid parameters", async () => {
    const response = await request(app).post("/login").send({
      username: "username",
      password: 12,
    });
    expect(response.statusCode).toBe(400);
  });

  test("Invalid request with invalid parameters", async () => {
    const response = await request(app).post("/login").send({
      password: 12,
    });
    expect(response.statusCode).toBe(400);
  });

  test("Invalid request with invalid parameters", async () => {
    const response = await request(app).post("/login").send(null);
    expect(response.statusCode).toBe(400);
  });

  test("Login successful", async () => {
    database.getUser.mockResolvedValueOnce({
      id: "id",
      username: "username",
      password:
        "92d690d4eb4a598d5362f7196dba110e3974a9ea58eb9363be73e987d738afc6",
      salt: "salt",
    });

    const response = await request(app).post("/login").send({
      username: "username",
      password:
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    });
    const cookies = extractCookies(response.headers);
    expect(cookies.refreshToken).toBeDefined();
    expect(response.statusCode).toBe(200);
  });

  test("Wrong password", async () => {
    database.getUser.mockResolvedValueOnce({
      id: "id",
      username: "username",
      password:
        "92d690d4eb4a598d5362f7196dba110e3974a9ea58eb9363be73e987d738afc6",
      salt: "salt",
    });

    const response = await request(app).post("/login").send({
      username: "username",
      password: "password",
    });
    const cookies = extractCookies(response.headers);
    expect(cookies.refreshToken).toBeUndefined();
    expect(response.statusCode).toBe(401);
  });

  test("User not found", async () => {
    database.getUser.mockImplementationOnce(() => {
      throw Error;
    });

    const response = await request(app).post("/login").send({
      username: "username",
      password: "password",
    });
    expect(response.statusCode).toBe(400);
  });
});

describe("POST /refresh", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  test("Invalid request without refresh token", async () => {
    const response = await request(app).post("/refresh");
    expect(response.statusCode).toBe(400);
  });

  test("Malformed token", async () => {
    const response = await request(app)
      .post("/refresh")
      .set("Cookie", `refreshToken=someToken;`)
      .send();
    expect(response.statusCode).toBe(400);
  });

  test("Refresh token does not exist", async () => {
    database.checkRefreshToken.mockImplementationOnce(() => {
      throw Error;
    });

    const token = jwt.sign({ userId: "mytestId1" }, HASURA_GRAPHQL_JWT_KEY);
    const response = await request(app)
      .post("/refresh")
      .set("Cookie", `refreshToken=${token};`)
      .send();
    expect(response.statusCode).toBe(400);
  });

  test("Refresh successful", async () => {
    database.checkRefreshToken.mockResolvedValueOnce(null);
    database.deleteRefreshToken.mockResolvedValueOnce(null);
    database.insertRefreshToken.mockResolvedValueOnce(null);

    const token = jwt.sign({ userId: "mytestId2" }, HASURA_GRAPHQL_JWT_KEY);
    const response = await request(app)
      .post("/refresh")
      .set("Cookie", `refreshToken=${token};`);

    const cookies = extractCookies(response.headers);
    expect(cookies.refreshToken).toBeDefined();
    expect(response.statusCode).toBe(200);
  });
});

describe("POST /logout", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  test("Invalid request without refresh token", async () => {
    const response = await request(app).post("/refresh");
    expect(response.statusCode).toBe(400);
  });

  test("Refresh token does not exist", async () => {
    database.deleteRefreshToken.mockImplementationOnce(() => {
      throw Error;
    });

    const token = jwt.sign({ userId: "mytestId1" }, HASURA_GRAPHQL_JWT_KEY);
    const response = await request(app)
      .post("/logout")
      .set("Cookie", `refreshToken=${token};`)
      .send();
    expect(response.statusCode).toBe(400);
  });

  test("Logout successful", async () => {
    database.deleteRefreshToken.mockResolvedValueOnce(null);

    const token = jwt.sign({ userId: "mytestId2" }, HASURA_GRAPHQL_JWT_KEY);
    const response = await request(app)
      .post("/logout")
      .set("Cookie", `refreshToken=${token};`)
      .send();
    expect(response.statusCode).toBe(200);
  });
});
