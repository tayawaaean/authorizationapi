const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
  refreshTokenId: { type: String, required: true }, // UUID v4
  userAgent: String,
  ip: String,
  geolocation: Object,
  createdAt: { type: Date, default: Date.now },
  lastUsedAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  revoked: { type: Boolean, default: false }
});

module.exports = mongoose.model('Session', sessionSchema);