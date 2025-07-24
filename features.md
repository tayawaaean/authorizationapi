# Features

- **User Registration**
  - Strong password enforcement and validation
  - Age verification (must be 13+)
  - reCAPTCHA protection
  - Terms of Service acceptance

- **Email Verification**
  - Users must verify their email before logging in
  - Verification link sent via email

- **Admin Approval**
  - All registrations require admin approval before login is allowed
  - Admin endpoints to approve or reject users

- **Secure Login**
  - Email and password authentication
  - Only verified and admin-approved users can log in

- **JWT Authentication & Per-Device Sessions**
  - JWT access and refresh tokens (refresh tokens are device/session-specific)
  - Users can view and revoke their active sessions/devices
  - Sessions are revoked after password reset or by user/admin action

- **Robust Password Reset**
  - Secure, one-time-use, short-lived reset tokens (expires in 30 minutes)
  - Rate limiting to prevent abuse and brute force
  - Generic responses to prevent account enumeration
  - All sessions are revoked after a successful password reset
  - Notification email sent after password change

- **Admin Management**
  - List, approve, and reject pending users
  - Protected admin routes (only admin/superadmin roles allowed)

- **Audit Logging**
  - Logs all important actions (login, registration, password reset, approvals, rejections)

- **Security Best Practices**
  - Helmet and CORS middleware for HTTP and cross-origin security
  - Rate limiting on sensitive endpoints
  - No account enumeration
  - Environment-based secrets management

- **Email Notifications**
  - Transactional emails for registration, verification, password reset, and password change

- **OpenAPI Documentation**
  - Interactive documentation available at `/api-docs`

---

For a concise version, you can also use this features section in your `README.md`.