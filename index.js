import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
// import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
  secret:"SENSITIVE",
  resave:false,
  saveUninitialized:true,
  cookie:{
    maxAge:2000
  }
}))

app.use(passport.initialize())
app.use(passport.session())

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "jk32@12345AA",
  port: 5432,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets",(req,res)=>{
  console.log("this user data comes from passport.serialization ",req.user)
  if (req.isAuthenticated()){
    res.render("secrets.ejs")
  }else{
    res.redirect("/login")
  }
})


app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
  
    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      // Save the plain text password in the database without hashing
      await db.query(
        "INSERT INTO users (email, password) VALUES ($1, $2)",
        [email, password]
      );
      res.render("secrets.ejs");
    }
  } catch (err) {
    console.log(err);
  }
  
});

app.post("/login", passport.authenticate("local",{
  successRedirect:"/secrets",
  failureRedirect:"/login",
  failureFlash:true
}));

passport.use(new Strategy(async function verify(username,password,cb){
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
  
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedPlainPassword = user.password;
  
      // Compare plain text passwords directly
      if (password === storedPlainPassword) {
        
        return cb(null,user)
        
      } else {
       return cb(null,false)
      }
    } else {
      return cb("User not Found")
    }
  } catch (err) {
    return cb(err)
  }
  

}))

passport.serializeUser((user,cb)=>{
  cb(null,user)
})

passport.deserializeUser((user,cb)=>{
  cb(null,user)
})


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
