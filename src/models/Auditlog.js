const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  eventType: { type: String, required: true }, // e.g. 'login_success', 'login_failure', 'password_change'
  ip: String,
  userAgent: String,
  location: Object,
  details: Object,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('AuditLog', auditLogSchema);