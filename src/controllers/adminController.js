const User = require('../models/User');
const logger = require('../utils/logger');

exports.listPendingUsers = async (req, res) => {
  try {
    const pendingUsers = await User.find({ registrationStatus: 'pending' });
    logger.info('Admin %s viewed pending users', req.user.email);
    res.json(pendingUsers);
  } catch (err) {
    logger.error('Error listing pending users: %s', err.message, { stack: err.stack });
    res.status(500).json({ msg: 'Failed to retrieve pending users.' });
  }
};

exports.approveUser = async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);
    if (!user) {
      logger.warn('Admin %s tried to approve non-existent user: %s', req.user.email, userId);
      return res.status(404).json({ msg: 'User not found.' });
    }
    user.registrationStatus = 'approved';
    await user.save();
    logger.info('Admin %s approved user %s', req.user.email, user.email);
    res.json({ msg: 'User approved.' });
  } catch (err) {
    logger.error('Error approving user: %s', err.message, { stack: err.stack });
    res.status(500).json({ msg: 'Failed to approve user.' });
  }
};

exports.rejectUser = async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);
    if (!user) {
      logger.warn('Admin %s tried to reject non-existent user: %s', req.user.email, userId);
      return res.status(404).json({ msg: 'User not found.' });
    }
    user.registrationStatus = 'rejected';
    await user.save();
    logger.info('Admin %s rejected user %s', req.user.email, user.email);
    res.json({ msg: 'User rejected.' });
  } catch (err) {
    logger.error('Error rejecting user: %s', err.message, { stack: err.stack });
    res.status(500).json({ msg: 'Failed to reject user.' });
  }
};