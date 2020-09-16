exports.checkAuthenticated = function (req, res, next) {
  if (req.isAuthenticated()) return res.redirect("/info")
  next()
}

exports.checkNotAuthenticated = function (req, res, next) {
  if (req.isAuthenticated()) return next()
  res.redirect("/")
}
