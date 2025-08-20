const request = require('supertest');
const app = require('../src/app'); // Adjust if your app entry point is elsewhere

// You may want to mock email sending and recaptcha for testing!
const validUser = {
  email: 'testuser@example.com',
  username: 'happy_user',
  password: 'StrongPass1!',
  recaptcha: 'dummy', // Should be mocked/disabled in test env
  tosAccepted: true,
  age: 21
};

let verificationToken;
let accessToken;
let refreshToken;

describe('Happy Path: User Registration Flow', () => {
  it('registers a user with valid data', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send(validUser);
    expect(res.statusCode).toBe(201);
    expect(res.body).toHaveProperty('message');
    // Assume the backend logs or emails a verification token for tests
    // You may need to fetch the token from DB or mock email
  });

  it('verifies user email', async () => {
    // Replace this with actual retrieval of the token (e.g., from DB or in-memory store)
    // Example: const user = await User.findOne({ email: validUser.email });
    // verificationToken = user.emailVerificationToken;
    verificationToken = 'mocked-or-fetched-token';

    // This next test will fail unless you implement a way to fetch the real token in your test DB
    const res = await request(app)
      .get(`/api/auth/verify-email?token=${verificationToken}`);
    // Depending on your implementation, expect a redirect or a success message
    expect([200, 302]).toContain(res.statusCode);
  });

  it('admin approves the user', async () => {
    // Simulate admin login and approval (this may require your admin credentials)
    // Here, we mock the approval for simplicity
    // You may need to fetch the userId from DB
    const userId = 'mocked-user-id';
    const adminToken = 'mocked-admin-token';

    const res = await request(app)
      .post('/api/admin/approve-user')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ userId });

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('message');
  });

  it('logs in with approved and verified user', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: validUser.email,
        password: validUser.password
      });
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
    accessToken = res.body.accessToken;
    refreshToken = res.body.refreshToken;
  });

  it('accesses a protected route with accessToken', async () => {
    const res = await request(app)
      .get('/api/auth/sessions') // Example protected route
      .set('Authorization', `Bearer ${accessToken}`);
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.body.sessions)).toBe(true);
  });
});