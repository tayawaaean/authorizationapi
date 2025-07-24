const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const logger = require('./utils/logger');


const app = express();

app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(express.json());

app.use((req, res, next) => {
  logger.info('%s %s', req.method, req.originalUrl);
  next();
});

app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);

module.exports = app;