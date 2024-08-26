import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import bcryptjs from "bcryptjs";
import jsonwebtoken from "jsonwebtoken";
import fakedb from "./fakedb.js";
import {
  createAccessToken,
  createRefreshToken,
  sendAccessToken,
  sendRefreshToken,
} from "./tokens.js";
import { isAuth } from "./isAuth.js";

const { compare, hash } = bcryptjs;
const { verify } = jsonwebtoken;

// 5. Get a new accesstoken with a refresh token

const server = express();

// use express middleware for easier cookie handling
server.use(cookieParser());

server.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);

// Needed to be able to read body data
server.use(express.json()); // to support JSON-encoded bodies
server.use(express.urlencoded({ extended: true })); // to support URL-encoded bodies

// 1. register a user

server.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    //1. validation of email and password
    if (!email) {
      throw new Error("Email is required");
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(email)) {
      throw new Error("Invalid email format");
    }

    if (!password) {
      throw new Error("Password is required");
    }
    // 2. check if the user exist

    const user = fakedb.find((user) => user.email === email);
    if (user) {
      throw new Error("User already exist");
    }
    // 3. if the user exist, hash the password
    const hashedPassword = await hash(password, 10);

    //4. insert the user in the fakeDb
    fakedb.push({
      id: fakedb.length + 1,
      email,
      password: hashedPassword,
    });

    res.status(201).send({ message: "User successfully created" });
    console.log(fakedb);
  } catch (error) {
    res.status(400).send({ error: `${error.message}` });
  }
});

// 2. login a user
server.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    //1 Find user in "database, if not exist send errors"
    const user = fakedb.find((user) => user.email === email);

    if (!user) throw new Error("user does not exist");

    //2 compare crypted psswod and see if it checks out, send error if not
    const valid = await compare(password, user.password);

    if (!valid) throw new Error("Password is incorrect");

    //3. create refresh and accesstoken
    const accessToken = createAccessToken(user.id);
    const refreshToken = createRefreshToken(user.id);

    //4 put the refreshtoken in the "database"
    user.refreshToken = refreshToken;
    console.log(fakedb);

    // 5 send the refresh token as a cookie and access toekn as a regular response

    sendRefreshToken(res, refreshToken);
    sendAccessToken(req, res, accessToken);
  } catch (error) {
    console.log(error);
    res.send({ error: `${error.message}` });
  }
});

// 3. logout a user

server.post("/logout", (req, res) => {
  res.clearCookie("refreshtoken", { path: "/refresh_token" });

  return res.send({
    message: "Logged out",
  });
});

// 4. setup a protected route
server.post("/protected", async (req, res) => {
  try {
    const userId = isAuth(req);

    if (userId !== null) {
      res.send({
        data: "this is protected data",
      });
    }
  } catch (error) {
    res.send({ error: ` ${error.message}` });
  }
});

// 5 get a new accesstoken with a refresh token

server.post("/refresh_token", (req, res) => {
  const token = req.cookies.refreshtoken;

  // if no token in request

  if (!token) return res.send({ accessToken: "" });
  //we have a token, lets verify it

  let payload = null;

  try {
    payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch (error) {
    return res.send({ accessToken: "" });
  }
  // token is valid , check if user exist
  const user = fakedb.find((user) => user.id === payload.userId);
  if (!user) return res.send({ accessToken: "" });
  //user exist, check if refresh token exists on user

  if (user.refreshToken !== token) {
    return res.send({ accessToken: "" });
  }

  // token exist, create new refresh and access token
  const accessToken = createAccessToken(user.id);
  const refreshToken = createRefreshToken(user.id);
  user.refreshToken = refreshToken;

  sendRefreshToken(res, refreshToken);
  return res.send({ accessToken });
});

server.listen(process.env.PORT, () => {
  console.log(fakedb);
  console.log(`server listening on port ${process.env.PORT}`);
});
