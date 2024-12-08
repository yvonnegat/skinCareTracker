const express = require('express');
const asyncHandler = require('express-async-handler');
const { check } = require('express-validator');
const { handleValidationErrors } = require('../../utils/validation');
const bcrypt = require('bcryptjs');
const { setTokenCookie, requireAuth } = require('../../utils/auth');
const { User, Task } = require('../../db/models');

const router = express.Router();

// Validation middleware for signup fields
const validateSignup = [
  check('email')
    .exists({ checkFalsy: true })
    .isEmail()
    .withMessage('Please provide a valid email.'),
  check('username')
    .exists({ checkFalsy: true })
    .isLength({ min: 4 })
    .withMessage('Please provide a username with at least 4 characters.'),
  check('username')
    .not()
    .isEmail()
    .withMessage('Username cannot be an email.'),
  check('password')
    .exists({ checkFalsy: true })
    .isLength({ min: 6 })
    .withMessage('Password must be 6 characters or more.'),
  handleValidationErrors,
];

// Test route to verify server setup
router.get('/test', asyncHandler(async (req, res) => {
  const users = await User.findAll();
  const tasks = await Task.findAll();
  return res.json({ name: "test", users, tasks });
}));

// Route to handle user signup
router.post(
  '/',
  validateSignup,
  asyncHandler(async (req, res, next) => {
    const { email, password, username } = req.body;

    // Check if the username already exists
    const existingUser = await User.findOne({ where: { username } });
    if (existingUser) {
      const err = new Error("Username already exists");
      err.status = 400;
      err.errors = ["Username already exists"];
      return next(err);
    }

    // Check if the email already exists
    const existingEmail = await User.findOne({ where: { email } });
    if (existingEmail) {
      const err = new Error("Email already exists");
      err.status = 400;
      err.errors = ["Email already exists"];
      return next(err);
    }

    // Hash the password and create the user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ email, username, hashedPassword });

    // Set the token cookie
    await setTokenCookie(res, user);

    // Return the new user info
    return res.json({ user });
  })
);

module.exports = router;
