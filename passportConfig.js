const LocalStrategy = require("passport-local").Strategy
const { pool } = require("./dbConfig")
const bcrypt = require("bcrypt")

function initialize(passport) {

  const authenticateUser = (email, password, done) => {
    pool.query(`SELECT * FROM users WHERE email = $1`, [email], (err, results) => {
      if (err) throw err

      if (results.rows.length > 0) {
        const user = results.rows[0]
        bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err)  console.error(err)

          isMatch ? done(null, user) : done(null, false, { message: "Password is incorrect" })
        })
      } else {
        return done(null, false, {message: "No user with that email address"})
      }
      }
    )
  }

  passport.use(new LocalStrategy({ usernameField: "email", passwordField: "password" }, authenticateUser))
  // Stores user details inside session. 
  passport.serializeUser((user, done) => done(null, user.id))

  // The fetched object is attached to the request object as req.user

  passport.deserializeUser((id, done) => {
    pool.query(`SELECT * FROM users WHERE id = $1`, [id], (err, results) => {
      if (err) return done(err)
      console.log(`ID is ${results.rows[0].id}`)
      return done(null, results.rows[0])
    })
  })
}

module.exports = initialize
