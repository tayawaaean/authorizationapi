const User = require('../models/User');
const Session = require('../models/Session');
const AuditLog = require('../models/Auditlog');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { validationResult } = require('express-validator');
const { sendResetEmail, sendVerificationEmail, sendWelcomeEmail, sendPasswordChangeNotification } = require('../utils/email');
const logger = require('../utils/logger');
const verifyRecaptcha = require('../utils/recaptcha');
const geoip = require('geoip-lite');


const MAX_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 minutes

// Registration
exports.register = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Validation failed during registration: %o', errors.array());
    return res.status(400).json({ msg: 'Invalid registration input.', errors: errors.array() });
  }

  const normalizedEmail = (req.body.email || '').trim().toLowerCase();
  const { password, username, tosAccepted, recaptcha, age } = req.body;

  // Age Verification
  if (age < 13) {
    logger.warn('Registration attempt by underaged user: %s', normalizedEmail);
    logger.info('Registration failed: underaged user (%s)', normalizedEmail);
    return res.status(400).json({ msg: 'You must be at least 13 years old to register.' });
  }

  // TOS Acceptance
  if (!tosAccepted) {
    logger.warn('User did not accept ToS: %s', normalizedEmail);
    logger.info('Registration failed: ToS not accepted (%s)', normalizedEmail);
    return res.status(400).json({ msg: 'You must accept the Terms of Service to register.' });
  }

  // reCAPTCHA verification
  const recaptchaValid = await verifyRecaptcha(recaptcha);
  if (!recaptchaValid) {
    logger.warn('Failed reCAPTCHA during registration for email: %s', normalizedEmail);
    logger.info('Registration failed: reCAPTCHA (%s)', normalizedEmail);
    return res.status(400).json({ msg: 'reCAPTCHA verification failed.' });
  }

  let existingUser = await User.findOne({ email: normalizedEmail });
  if (existingUser) {
    const now = Date.now();
    if (
      !existingUser.isVerified &&
      existingUser.registrationLockedUntil &&
      now < existingUser.registrationLockedUntil.getTime()
    ) {
      logger.warn('Registration locked for email: %s', normalizedEmail);
      logger.info('Registration failed: email locked out (%s)', normalizedEmail);
      return res.status(429).json({ msg: 'Too many registration attempts for this email. Please try again later.' });
    }
  }

  try {
    // Granular duplicate checks
    let existingUsername = await User.findOne({ username: username.trim() });

    // Granular error feedback for email and username
    if (existingUser && existingUser.isVerified) {
      logger.info('Registration failed: email already in use (%s)', normalizedEmail);
      return res.status(400).json({ msg: 'Email already in use.' });
    }
    if (existingUsername) {
      logger.info('Registration failed: username already taken (%s)', username);
      return res.status(400).json({ msg: 'Username already taken.' });
    }
    if (existingUser && !existingUser.isVerified) {
      // Increment failed attempts for email (unverified only)
      existingUser.failedRegistrationAttempts = (existingUser.failedRegistrationAttempts || 0) + 1;
      if (existingUser.failedRegistrationAttempts >= MAX_ATTEMPTS) {
        existingUser.registrationLockedUntil = new Date(Date.now() + LOCK_TIME);
        existingUser.failedRegistrationAttempts = 0;
        logger.warn('User email locked out due to repeated failed attempts: %s', normalizedEmail);
      }
      await existingUser.save();
      logger.info('Registration failed: unverified email exists (%s)', normalizedEmail);
      return res.status(400).json({ msg: 'A verification email has already been sent to this address. Please check your inbox.' });
    }

    // Hash the password
    const hashed = await bcrypt.hash(password, 12);

    // Geolocation and IP logging
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const geo = geoip.lookup(ip);

    // Email verification
    const emailVerificationToken = crypto.randomBytes(32).toString('hex');
    const emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

    // Create user
    const user = await User.create({
      email: normalizedEmail,
      password: hashed,
      username,
      tosAccepted,
      ip,
      geolocation: geo,
      emailVerificationToken,
      emailVerificationExpires,
      isVerified: false,
      registrationStatus: 'pending',
      age,
      failedRegistrationAttempts: 0,
      registrationLockedUntil: undefined,
      refreshTokenVersion: 0
    });

    logger.info('User registered successfully (pending approval): %s (IP: %s, Geo: %o)', normalizedEmail, ip, geo);

    // Send verification and welcome emails
    await sendVerificationEmail(user.email, emailVerificationToken);
    await sendWelcomeEmail(user.email, username);
    user.welcomeEmailSent = true;
    await user.save();

    res.status(201).json({ msg: 'Registration successful! Please check your email to verify your account. Your registration is pending admin approval.' });
  } catch (err) {
    // On error, increment failed attempts for email (unverified only)
    if (existingUser && !existingUser.isVerified) {
      existingUser.failedRegistrationAttempts = (existingUser.failedRegistrationAttempts || 0) + 1;
      if (existingUser.failedRegistrationAttempts >= MAX_ATTEMPTS) {
        existingUser.registrationLockedUntil = new Date(Date.now() + LOCK_TIME);
        existingUser.failedRegistrationAttempts = 0;
        logger.warn('User email locked out due to repeated failed attempts: %s', normalizedEmail);
      }
      await existingUser.save();
    }
    logger.error('Error during registration: %s', err.message, { stack: err.stack });
    logger.info('Registration failed: server error (%s)', normalizedEmail);
    res.status(500).json({ msg: 'Registration failed. Please check your details and try again.' });
  }
};

// Login with session creation
exports.login = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.info('Login failed: validation error');
    return res.status(400).json({ errors: errors.array() });
  }

  const normalizedEmail = (req.body.email || '').trim().toLowerCase();
  const { password } = req.body;
  try {
    const user = await User.findOne({ email: normalizedEmail });
    let failMsg = 'Invalid credentials';
    let failCode = 400;

    if (!user) {
      logger.info('Login failed: email not found (%s)', normalizedEmail);
      return res.status(failCode).json({ msg: failMsg });
    }

    const now = Date.now();
    if (
      user.failedLoginAttempts >= 5 &&
      user.loginLockedUntil &&
      now < user.loginLockedUntil.getTime()
    ) {
      logger.warn('Login locked for email: %s', normalizedEmail);
      logger.info('Login failed: account locked out (%s)', normalizedEmail);
      return res.status(429).json({ msg: 'Too many failed login attempts. Please try again later.' });
    }

    if (!user.isVerified) {
      logger.info('Login failed: email not verified (%s)', normalizedEmail);
      return res.status(403).json({ msg: 'Please verify your email before logging in.' });
    }
    if (user.registrationStatus !== 'approved') {
      logger.info('Login failed: registration not approved (%s)', normalizedEmail);
      return res.status(403).json({ msg: 'Your registration is still pending admin approval.' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      if (user.failedLoginAttempts >= 5) {
        user.loginLockedUntil = new Date(now + 15 * 60 * 1000);
        logger.warn('User login locked out due to repeated failed attempts: %s', normalizedEmail);
      }
      await user.save();
      logger.info('Login failed: invalid password (%s)', normalizedEmail);
      return res.status(failCode).json({ msg: failMsg });
    }

    // Reset failed attempts
    user.failedLoginAttempts = 0;
    user.loginLockedUntil = undefined;
    await user.save();

    // JWT tokens
    const payload = { userId: user._id, usertype: user.usertype };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });

    // Device/session management
    const refreshTokenId = uuidv4();
    const refreshToken = jwt.sign(
      {
        ...payload,
        tokenType: 'refresh',
        refreshTokenId
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    await Session.create({
      userId: user._id,
      refreshTokenId,
      userAgent: req.headers['user-agent'],
      ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      geolocation: geoip.lookup(req.headers['x-forwarded-for'] || req.connection.remoteAddress),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    logger.info('Login successful: %s', normalizedEmail);
    return res.json({
      accessToken,
      user: { id: user._id, email: user.email, usertype: user.usertype }
    });
  } catch (err) {
    logger.error('Error during login: %s', err.message, { stack: err.stack });
    return res.status(500).json({ msg: 'Server error' });
  }
};

// Refresh Token endpoint with rotation & session management
exports.refreshToken = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ msg: 'No refresh token.' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user || user.status !== 'active') {
      return res.status(401).json({ msg: 'User not found or inactive.' });
    }

    // Find session by refreshTokenId
    const session = await Session.findOne({
      userId: decoded.userId,
      refreshTokenId: decoded.refreshTokenId,
      revoked: false,
      expiresAt: { $gt: Date.now() }
    });
    if (!session) {
      // Possible token theft or replay; revoke all sessions for user
      await Session.updateMany({ userId: decoded.userId }, { revoked: true });
      res.clearCookie('refreshToken');
      return res.status(401).json({ msg: 'Session invalid or expired. Please log in again.' });
    }

    // Rotate: revoke this session, create a new one
    session.revoked = true;
    await session.save();

    const newRefreshTokenId = uuidv4();
    const payload = { userId: user._id, usertype: user.usertype };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
    const newRefreshToken = jwt.sign(
      {
        ...payload,
        tokenType: 'refresh',
        refreshTokenId: newRefreshTokenId
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    await Session.create({
      userId: user._id,
      refreshTokenId: newRefreshTokenId,
      userAgent: req.headers['user-agent'],
      ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      geolocation: geoip.lookup(req.headers['x-forwarded-for'] || req.connection.remoteAddress),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ accessToken });
  } catch (err) {
    res.clearCookie('refreshToken');
    return res.status(401).json({ msg: 'Invalid or expired refresh token.' });
  }
};

// View active sessions/devices
exports.getSessions = async (req, res) => {
  const userId = req.user._id;
  const sessions = await Session.find({ userId, revoked: false })
    .select('-_id refreshTokenId userAgent ip geolocation createdAt lastUsedAt expiresAt');
  res.json({ sessions });
};

// Revoke session/device
exports.revokeSession = async (req, res) => {
  const userId = req.user._id;
  const { refreshTokenId } = req.body;
  const session = await Session.findOne({ userId, refreshTokenId, revoked: false });
  if (!session) return res.status(404).json({ msg: 'Session not found.' });
  session.revoked = true;
  await session.save();
  res.json({ msg: 'Session revoked.' });
};

exports.forgotPassword = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.info('Forgot password failed: validation error');
    // Always return generic message
    return res.status(200).json({ msg: 'If an account exists, you will receive a password reset email.' });
  }

  const normalizedEmail = (req.body.email || '').trim().toLowerCase();
  try {
    const user = await User.findOne({ email: normalizedEmail });
    if (user) {
      const resetToken = crypto.randomBytes(32).toString('hex');
      user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
      user.resetPasswordExpires = Date.now() + 30 * 60 * 1000; // 30 minutes
      await user.save();

      await sendResetEmail(user.email, resetToken);

      // Audit log for reset requested
      await AuditLog.create({
        userId: user._id,
        eventType: 'password_reset_requested',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { success: true }
      });
    }
    // Always return generic message (do not reveal user existence)
    logger.info('Forgot password requested for %s (generic response sent)', normalizedEmail);
    return res.status(200).json({ msg: 'If an account exists, you will receive a password reset email.' });
  } catch (err) {
    logger.error('Error during forgotPassword: %s', err.message, { stack: err.stack });
    // Always return generic message
    res.status(200).json({ msg: 'If an account exists, you will receive a password reset email.' });
  }
};

exports.resetPassword = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.info('Reset password failed: validation error');
    return res.status(400).json({ errors: errors.array() });
  }

  const { token, password } = req.body;
  try {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() }
    });
    if (!user) {
      logger.info('Reset password failed: invalid or expired token');
      // Audit log for failed reset
      await AuditLog.create({
        eventType: 'password_reset_failed',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details: { reason: 'invalid or expired token' }
      });
      return res.status(400).json({ msg: 'Invalid or expired token' });
    }

    user.password = await bcrypt.hash(password, 12);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    // Invalidate all user sessions after reset
    await Session.updateMany({ userId: user._id }, { revoked: true });
    user.refreshTokenVersion += 1;
    await user.save();

    // Send notification email
    await sendPasswordChangeNotification(user.email);

    // Audit log for successful reset
    await AuditLog.create({
      userId: user._id,
      eventType: 'password_reset_success',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      details: { method: 'reset_password', success: true }
    });

    logger.info('Password reset successful for user: %s', user.email);
    res.json({ msg: 'Password reset successful' });
  } catch (err) {
    logger.error('Error during resetPassword: %s', err.message, { stack: err.stack });
    res.status(500).json({ msg: 'Server error' });
  }
};

// Email Verification Handler
exports.verifyEmail = async (req, res) => {
  const { token } = req.query;
  try {
    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: Date.now() }
    });
    if (!user) {
      logger.info('Email verification failed: invalid or expired token');
      return res.status(400).json({ msg: 'Invalid or expired verification token.' });
    }
    user.isVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    user.failedRegistrationAttempts = 0;
    user.registrationLockedUntil = undefined;
    await user.save();
    logger.info('Email successfully verified: %s', user.email);
    res.json({ msg: 'Email successfully verified! You can now log in, pending admin approval.' });
  } catch (err) {
    logger.error('Error during email verification: %s', err.message, { stack: err.stack });
    res.status(500).json({ msg: 'Server error' });
  }
};