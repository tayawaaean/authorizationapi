const axios = require('axios');

async function verifyRecaptcha(token) {
  if (process.env.NODE_ENV === 'development' && token === 'dummy') {
    return true; // Bypass for local testing
  }
  const secret = process.env.RECAPTCHA_SECRET;
  try {
    const response = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify?secret=${secret}&response=${token}`
    );
    return response.data.success;
  } catch {
    return false;
  }
}

module.exports = verifyRecaptcha;