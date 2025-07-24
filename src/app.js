const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const logger = require('./utils/logger');

// --- Swagger UI setup ---
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const swaggerDocument = YAML.load('./openapi.yaml');
// ------------------------

const app = express();

app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(express.json());

app.use((req, res, next) => {
  logger.info('%s %s', req.method, req.originalUrl);
  next();
});

app.get('/', (req, res) => {
  res.send('API is running. See /api-docs for documentation.');
});

// --- Swagger docs route ---
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
// --------------------------

app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);

module.exports = app;