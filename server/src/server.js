import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import jsonwebtoken from "jsonwebtoken";
import bcryptjs from "bcryptjs";

const { compare, hash } = bcryptjs;
const { verify } = jsonwebtoken;

// 1. register a user

// 2. login a user

// 3. logout a user

// 4. setup a protected route

//5. Get a new accesstoken with a refresh token

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

server.listen(process.env.PORT, () => {
  console.log(`server listening on port ${process.env.PORT}`);
});
