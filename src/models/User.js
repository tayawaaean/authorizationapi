const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  password: { type: String, required: true },

  usertype: {
    type: String,
    enum: ['user', 'admin', 'superadmin'],
    default: 'user'
  },

  isVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: String,
  emailVerificationExpires: Date,

  resetPasswordToken: String,
  resetPasswordExpires: Date,

  // Account status and registration flow
  status: {
    type: String,
    enum: ['active', 'suspended', 'deleted'],
    default: 'active'
  },

  registrationStatus: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },

  tosAccepted: {
    type: Boolean,
    required: true
  },
  age: {
    type: Number,
    required: true,
    min: 13
  },

  ip: String,
  geolocation: Object,

  welcomeEmailSent: { type: Boolean, default: false },

  // Registration lockout (for repeated failed registration attempts)
  failedRegistrationAttempts: {
    type: Number,
    default: 0
  },
  registrationLockedUntil: Date,

  // Login lockout (for brute-force defense)
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  loginLockedUntil: Date,

  // For refresh token rotation & invalidation
  refreshTokenVersion: {
    type: Number,
    default: 0
  }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);