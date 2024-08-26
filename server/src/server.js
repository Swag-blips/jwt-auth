import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import jsonwebtoken from "jsonwebtoken";
import bcryptjs from "bcryptjs";
import fakedb from "./fakedb.js";

const { compare, hash } = bcryptjs;
const { verify } = jsonwebtoken;

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

server.listen(process.env.PORT, () => {
  console.log(`server listening on port ${process.env.PORT}`);
});
