const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports = async function (req, res, next) {
  try {
    let token = null;
    // Prefer Authorization header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies && req.cookies.refreshToken) {
      token = req.cookies.refreshToken;
    }
    if (!token) {
      return res.status(401).json({ msg: 'No token, authentication denied.' });
    }
    // DEBUG: log the token and secret for troubleshooting (remove in production)
    // console.log("Token:", token);
    // console.log("JWT_SECRET:", process.env.JWT_SECRET);

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || (user.usertype !== 'admin' && user.usertype !== 'superadmin')) {
      return res.status(403).json({ msg: 'Not authorized as admin.' });
    }
    req.user = user;
    next();
  } catch (err) {
    // Improved error logging for debugging
    // console.error('JWT Error:', err);
    return res.status(401).json({ msg: 'Token is not valid.', error: err.message });
  }
}