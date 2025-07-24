const express = require('express');
const { body } = require('express-validator');
const rateLimit = require('express-rate-limit');
const authController = require('../controllers/authController');
const auth = require('../middleware/authAdmin'); // JWT access token middleware

// Rate limiter for registration route
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many registration attempts. Please try again later.'
});

// Rate limiter for reset password route
const resetPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many password reset attempts. Please try again later.'
});

const router = express.Router();

// Registration route
router.post(
  '/register',
  registerLimiter,
  [
    body('email')
      .isEmail().withMessage('Invalid email address')
      .normalizeEmail(),
    body('username')
      .isLength({ min: 3, max: 30 }).withMessage('Username must be 3-30 characters')
      .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers, and underscores'),
    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
      .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
      .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
      .matches(/[0-9]/).withMessage('Password must contain a number')
      .matches(/[^A-Za-z0-9]/).withMessage('Password must contain a symbol'),
    body('recaptcha').notEmpty().withMessage('reCAPTCHA token is required'),
    body('tosAccepted').equals('true').withMessage('Terms of Service must be accepted'),
    body('age')
      .isInt({ min: 13 }).withMessage('You must be at least 13 years old to register.')
  ],
  authController.register
);

// Login route
router.post(
  '/login',
  [
    body('email').isEmail(),
    body('password').notEmpty()
  ],
  authController.login
);

// Refresh token rotation endpoint
router.post('/refresh-token', authController.refreshToken);

// Forgot password route
// Forgot password route
router.post(
  '/forgot-password',
  [body('email').isEmail()],
  authController.forgotPassword
);

// Reset password route with limiter
router.post(
  '/reset-password',
  resetPasswordLimiter,
  [
    body('token').notEmpty(),
    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
      .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
      .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
      .matches(/[0-9]/).withMessage('Password must contain a number')
      .matches(/[^A-Za-z0-9]/).withMessage('Password must contain a symbol')
  ],
  authController.resetPassword
);

// Email verification route (for clicking verification link in email)
router.get('/verify-email', authController.verifyEmail);

// Device/session management
router.get('/sessions', auth, authController.getSessions);
router.post('/revoke-session', auth, authController.revokeSession);

module.exports = router;