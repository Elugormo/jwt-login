const router = require("express").Router();
const AuthController = require("../controllers/AuthController");
const Middleware = require("../middlewares");

router.post("/auth/signup", AuthController.signup);

router.post("/auth/login", AuthController.login);

router.post("/auth/refresh_token", AuthController.generateRefreshToken);

router.delete("/auth/logout", AuthController.logout);

router.get("/protected_resource", Middleware.checkAuth, (req, res) => {
  return res.status(200).json({ user: req.user });
});

module.exports = router;
