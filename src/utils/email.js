
const nodemailer = require('nodemailer');


const isDev = process.env.NODE_ENV === "development";

const transporter = !isDev
  ? nodemailer.createTransport({
      host: "smtp.office365.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    })
  : null;

exports.sendResetEmail = async (to, token) => {
  if (isDev) {
    console.log(`[DEV] Would send password reset email to ${to} with token: ${token}`);
    return;
  }
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
  await transporter.sendMail({
    to,
    subject: 'Password Reset',
    html: `<p>Reset your password: <a href="${resetUrl}">${resetUrl}</a></p>`,
  });
};

exports.sendVerificationEmail = async (to, token) => {
  if (isDev) {
    console.log(`[DEV] Would send verification email to ${to} with token: ${token}`);
    return;
  }
  const verifyUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
  await transporter.sendMail({
    to,
    subject: 'Verify your email address',
    html: `<p>Verify your email address by clicking here: <a href="${verifyUrl}">${verifyUrl}</a></p>`,
  });
};

exports.sendWelcomeEmail = async (to, username) => {
  if (isDev) {
    console.log(`[DEV] Would send welcome email to ${to} for user: ${username}`);
    return;
  }
  await transporter.sendMail({
    to,
    subject: 'Welcome!',
    html: `<p>Welcome to our service, ${username}!</p>`,
  });
};

exports.sendPasswordChangeNotification = async (to) => {
  if (isDev) {
    console.log(`[DEV] Would send password change notification email to ${to}`);
    return;
  }
  await transporter.sendMail({
    to,
    subject: 'Your password has been changed',
    html: `<p>Your password has been changed. If this wasn't you, please contact our support immediately.</p>`,
  });
};