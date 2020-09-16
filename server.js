require("dotenv").config()
const express = require("express")
const { pool } = require("./dbConfig")
const bcrypt = require("bcrypt")
const passport = require("passport")
const flash = require("express-flash")
const session = require("express-session")
const app = express()
const path = require('path')
const fileUpload = require('express-fileupload')

const controller = require('./controllers/index')
const authMiddleware = require('./middleware/auth')

const PORT = process.env.PORT || 5000
const storage = []

const initializePassport = require("./passportConfig")
const { error } = require("console")
initializePassport(passport)

app.use(express.urlencoded({ extended: false }))
app.set("view engine", "ejs")
app.use(express.static(path.join(__dirname, 'public')))
app.use(session({
    secret: process.env.SESSION_SECRET,
    saveUninitialized: false,
    resave: true,
    rolling: true,
    //renew the session automatically and it will only expire when it has been idle for the value in the expires variable
    cookie: {
      expires: 1000 * 60 * 10
    }
  }))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())
app.use(fileUpload({
  limits: { fileSize: 1024 * 1024 * 5 },
}));

app.get("/", controller.index)

app.get("/signup", authMiddleware.checkAuthenticated, (req, res) => {
  res.render("signup.ejs")
})

app.get("/signin", authMiddleware.checkAuthenticated, (req, res) => {
  res.render("signin.ejs")
})

app.get("/info", authMiddleware.checkNotAuthenticated, (req, res) => {
  res.render("info.ejs", { userId: req.user.id })
  console.log(req.session.cookie._expires);
})

app.get("/logout", (req, res) => {
  req.logout()
  res.render("logout.ejs", { message: "You have logged out successfully" })
})

app.post("/signup", async (req, res) => {
  let { name, email, password } = req.body
  let errors = []

  if (!name || !email || !password) errors.push({ message: "Please enter all fields" })
  if (password.length < 6) errors.push({ message: "Password must be a least 6 characters long" })
  if (errors.length > 0) res.render("signup.ejs", { errors, name, email, password})
  
  hashedPassword = await bcrypt.hash(password, 10) 

  pool.query(`SELECT * FROM users WHERE email = $1`, [email], (err, results) => {
      if (err) console.error(err)
      
      if (results.rows.length > 0) {
        return res.render("signup.ejs", { message: "Email is already in use" })
      } else {
        pool.query(`INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, password`,[name, email, hashedPassword],(err, results) => {
          if (err) throw err
          req.flash("success_msg", "You are now signuped. Please log in")
          res.redirect("/signin")
          }
        )
      }
    }
  )
})

app.post("/signin", passport.authenticate("local", {
    successRedirect: "/info",
    failureRedirect: "/signin",
    failureFlash: true
  })
)

app.post("/file/upload", authMiddleware.checkNotAuthenticated, (req, res) => {
  if (!req.files) return res.redirect('/info')

  const userId = +req.user.id
  const timeStamp = new Date().getTime().toString()
  const {name, size, mimetype, mv} = req.files['file-input']
  const uniqueFileNamePath = `/uploads/${timeStamp}-${name}`
  
  const file = {name, size, mimetype, timeStamp, uniqueFileNamePath, userId}

  mv(path.join(__dirname, `${uniqueFileNamePath}`), (err) => {
    if (err) console.error(err)
  }) 
  
  pool.query(`
    INSERT INTO files (filename, size, mimetype, timestamp, uniquefilenamepath, userid) 
    VALUES ($1, $2, $3, $4, $5, $6) RETURNING * `,
    [name, size, mimetype, timeStamp, uniqueFileNamePath, userId],(err, results) => {
      if (err) throw err
      const data = results.rows[0]
      console.log(data);
      res.render('file.ejs', {
        id: data.id,
        filename: data.filename,
        size: data.size,
        mimetype: data.mimetype,
        timestamp:data.timestamp,
        uniquefilenamepath:data.uniquefilenamepath,
        userid: data.userid
      })
  })
})

app.get("/file/upload", authMiddleware.checkNotAuthenticated, (req, res) => {
  res.render("upload.ejs")
})

app.get("/file/list", authMiddleware.checkNotAuthenticated, (req, res) => {
  
  let limit
  let page
  req.params.limit ? limit = req.params.limit : limit = 10 
  req.params.offset ? page = req.params.offset : page = 1

  pool.query(`SELECT * FROM files WHERE userid = $1 LIMIT $2`, [req.user.id, limit], (err, result) => {
    if (err) console.error(err)
    const arrayOfFiles = result.rows
    res.render("file_list.ejs", {arrayOfFiles})
  })
})

app.get("/file/:id", authMiddleware.checkNotAuthenticated, (req, res) => {
  pool.query(`SELECT * FROM files WHERE id = $1`, [req.params.id], (err, result) => {
    if (err) console.error(err)
    const file = result.rows[0]
    res.render('file.ejs', { file })
  })
})

app.delete("/file/delete/:id", authMiddleware.checkNotAuthenticated, (req, res) => {
  pool.query(`DELETE FROM files where id = $1`, [req.params.id], (err, result) => {
    if (err) console.error(err)
    res.status(200).json({message: 'File has been removed'})
  })
})

app.put("/file/update/:id", authMiddleware.checkNotAuthenticated, (req, res) => {
  pool.query(
    'UPDATE files SET filename = $1, size = $2, mimetype = $3 timestamp = $4 uniquefilenamepath = $5 where id = $6 returning *', 
    [filename, size, mimetype,timestamp,uniquefilenamepath, req.params.id], (err, result) => {
      if (err) console.error(err)
      res.status(200).json({message: 'File has been updated'})
  })
})

app.get("/file/download/:id", authMiddleware.checkNotAuthenticated, (req, res) => {
  pool.query(`SELECT * FROM files WHERE id = $1`, [req.params.id], (err, result) => {
    if (err) console.error(err)
    const file = result.rows[0]
    res.download(__dirname + `${file.uniquefilenamepath}`)
  })
})

app.listen(PORT, () => console.log(`Server running on port ${PORT}`))
