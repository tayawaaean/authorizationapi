const express = require('express');
const adminController = require('../controllers/adminController');
const authAdmin = require('../middleware/authAdmin');

const router = express.Router();

router.get('/pending-users', authAdmin, adminController.listPendingUsers);
router.post('/approve-user', authAdmin, adminController.approveUser);
router.post('/reject-user', authAdmin, adminController.rejectUser);

module.exports = router;