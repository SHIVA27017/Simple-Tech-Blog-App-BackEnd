import express from "express";
import sanitizeHTML from "sanitize-html";
import dotenv from "dotenv";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { marked } from "marked";

// sqlite3 database setup
const db = new Database("./databases/newsDB.db");
db.pragma("journal_mode=WAL");

// table

const createTable = db.transaction(() => {
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )
    `
  ).run();

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS posts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    title STRING NOT NULL,
    content TEXT NOT NULL,
    authorid INTEGER,
    FOREIGN KEY (authorid) REFERENCES users(id)
    )
    `
  ).run();
});

createTable();

const app = express();
dotenv.config();
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: false })); // extended:false ?

app.use(function (request, response, next) {
  // markdown support

  response.locals.filterUserHTML = function (content) {
    return sanitizeHTML(marked.parse(content), {
      allowedTags: [
        "p",
        "br",
        "ul",
        "li",
        "em",
        "i",
        "strong",
        "ol",
        "bold",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
      ],
      allowedAttributes: {},
    });
  };

  response.locals.errors = [];

  // try to decode the incomming requests

  try {
    const decodeToken = jwt.verify(
      request.cookies.techNewsApp,
      process.env.JWTSECRETE
    );
    // console.log(`decodeToken- ${decodeToken.username}`);
    request.user = decodeToken;
  } catch (error) {
    request.user = false;
  }
  response.locals.user = request.user;
  // console.log(request.user);
  next();
});
// serve ejs files:
app.use(express.static("public"));
app.set("view engine", "ejs");
app.get("/", (request, response) => {
  if (request.user) {
    const fetchPosts = db.prepare(
      "SELECT * FROM posts WHERE authorid=? ORDER BY createdDate DESC"
    );
    const posts = fetchPosts.all(request.user.userid);
    return response.render("dashboard", { posts });
  }
  return response.render("index");
  // return request.user ? response.render("dashboard") : response.render("index");
});

app.get("/login", (_, response) => {
  return response.render("login");
});

app.get("/logout", (_, response) => {
  response.clearCookie("techNewsApp");
  return response.redirect("/");
});

// routes:

function mustBeLoggedIn(request, response, next) {
  if (request.user) return next();
  return response.redirect("/");
}

app.get("/create-post", mustBeLoggedIn, (_, response) => {
  return response.render("create-post");
});

app.post("/login", async (request, response) => {
  let errors = [];
  if (typeof request.body.username !== "string") request.body.username = "";
  if (typeof request.body.password !== "string") request.body.password = "";

  if (request.body.username.trim() === "")
    errors = ["Invalid username/password"];
  if (request.body.password === "") errors = ["Invalid username/password"];

  if (errors.length) {
    return response.render("login", { errors });
  }

  const findUserStatement = db.prepare("SELECT * FROM users WHERE username=?");
  const user = findUserStatement.get(request.body.username);
  // console.log(user);

  if (!user) {
    errors = ["Invalid username/password"];
    return response.render("login", { errors });
  }

  const isPaswdMatch = await bcrypt.compare(
    request.body.password,
    user.password
  );

  if (!isPaswdMatch) {
    errors = ["Invalid username/password"];
    return response.render("login", { errors });
  }

  const token = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      userid: user.id,
      username: user.username,
    },
    process.env.JWTSECRETE
  );

  // set the cookie

  response.cookie("techNewsApp", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24,
  });

  return response.redirect("/");
});

app.post("/register", async (request, response) => {
  const errors = [];
  // console.log(request.body.username, request.body.password);
  if (typeof request.body.username !== "string") request.body.username = "";
  if (typeof request.body.password !== "string") request.body.password = "";

  request.body.username = request.body.username.trim();

  // username validation
  if (!request.body.username) errors.push("You must provide a username. ");
  if (request.body.username && request.body.username.length < 3)
    errors.push("Username must be atleast 3 characters ");
  if (request.body.username && request.body.username.length > 10)
    errors.push("Username can't exceed 10 characters");

  if (request.body.username && !request.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push("Username can only contain letters and numbers");

  // check username already exists or not

  const userNameFinder = db.prepare("SELECT * FROM users WHERE username=?");
  const userNameCheck = userNameFinder.get(request.body.username);
  if (userNameCheck) errors.push("username already taken.");

  // password validation
  if (!request.body.password) errors.push("You must provide a password. ");
  if (request.body.password && request.body.password.length < 7)
    errors.push("Password must be atleast 12 characters ");
  if (request.body.password && request.body.password.length > 17)
    errors.push("Password can't exceed 17 characters");

  if (errors.length) {
    return response.render("index", { errors });
  }

  // save the user to db

  const hashPwd = await bcrypt.hash(request.body.password, 10);
  const statement = db.prepare(
    "INSERT INTO users (username,password) VALUES (?,?)"
  );
  const results = statement.run(request.body.username, hashPwd);

  // get user from database

  const lookUpStatement = db.prepare("SELECT * FROM users WHERE ROWID=?");
  const User = lookUpStatement.get(results.lastInsertRowid);
  // console.log(User);
  // console.log(User.id);

  // jsonwebtoken

  const token = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      userid: User.id,
      username: User.username,
    },
    process.env.JWTSECRETE
  );

  // set the cookie

  response.cookie("techNewsApp", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24,
  });

  // return response.send(`<h1>Hey ${request.body.username},Thank you!</h1>`);
  return response.redirect("/");
});

app.get("/posts/:id", (request, response) => {
  const statement = db.prepare(
    "SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id=?"
  );
  const post = statement.get(request.params.id);
  if (!post) return response.redirect("/");

  // check if aurhor or different author i maen user

  const isAuthor = post.authorid === request.user.userid;

  return response.render("single-post", { post, isAuthor });
});

function sharedPostValidation(request) {
  const errors = [];

  if (typeof request.body.title !== "string") request.body.title = "";
  if (typeof request.body.content !== "string") request.body.content = "";

  // sanitize html or any js scripts

  request.body.title = sanitizeHTML(request.body.title.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  request.body.content = sanitizeHTML(request.body.content.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  if (!request.body.title) errors.push("You must provide a title.");
  if (!request.body.content) errors.push("You must provide a content.");

  return errors;
}

app.post("/create-post", mustBeLoggedIn, (request, response) => {
  const errors = sharedPostValidation(request);

  if (errors.length) return response.render("create-post", { errors });

  // if there are no errors, store in db

  console.log(`USER ID: ${request.user.userid}`);

  const Posts = db.prepare(
    "INSERT INTO posts (createdDate,title,content,authorid) VALUES (?,?,?,?)"
  );
  const results = Posts.run(
    new Date().toISOString(),
    request.body.title,
    request.body.content,
    request.user.userid
  );

  // console.log(results);

  const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID=?");
  const realPost = getPostStatement.get(results.lastInsertRowid);

  return response.redirect(`/posts/${realPost.id}`);
});

// edit-post
app.get("/edit-post/:id", mustBeLoggedIn, (request, response) => {
  // get the post from db if its exists based on id
  const getPost = db.prepare("SELECT * FROM posts WHERE id=?");
  const post = getPost.get(request.params.id);

  // if post is undefined then redirect to home page
  if (!post) return response.redirect("/");
  // if your not author then redirect to homepage '/'

  if (post.authorid !== request.user.userid) {
    return response.redirect("/");
  }

  //otherwise redirect to edit route

  return response.render("edit-post", { post });
});

// edit-post and the update post in db
app.post("/edit-post/:id", mustBeLoggedIn, (request, response) => {
  // get the post from db if its exists based on id
  const getPost = db.prepare("SELECT * FROM posts WHERE id=?");
  const post = getPost.get(request.params.id);

  // if post is undefined then redirect to home page
  if (!post) return response.redirect("/");
  // if your not author then redirect to homepage '/'

  if (post.authorid !== request.user.userid) {
    return response.redirect("/");
  }

  const errors = sharedPostValidation(request);

  if (errors.length) {
    return response.render("edit-post", { errors });
  }

  const updatePostStatement = db.prepare(
    "UPDATE posts SET title=?,content=? WHERE id=?"
  );
  const updatedPost = updatePostStatement.run(
    request.body.title,
    request.body.content,
    request.params.id
  );

  return response.redirect(`/posts/${request.params.id}`);
});

// delete post
app.post("/delete-post/:id", mustBeLoggedIn, (request, response) => {
  // get the post from db if its exists based on id
  const getPost = db.prepare("SELECT * FROM posts WHERE id=?");
  const post = getPost.get(request.params.id);

  // if post is undefined then redirect to home page
  if (!post) return response.redirect("/");
  // if your not author then redirect to homepage '/'

  if (post.authorid !== request.user.userid) {
    return response.redirect("/");
  }

  const deletePostStatement = db.prepare("DELETE FROM posts WHERE id=?");
  deletePostStatement.run(request.params.id);

  return response.redirect("/");
});

app.listen(process.env.PORT || 3000, () =>
  console.log(`App listening on port: ${process.env.PORT || 3000}`)
);
