import express from 'express';
import {
  registerUser,
  loginUser,
  getMe,
  refreshToken,
  logoutUser,
  forgotPassword, 
  resetPassword
} from '../controllers/authController.js';

import { protect, authorizeRoles } from '../middlewares/authMiddleware.js';
import { validateRegister, validateLogin } from '../middlewares/validateInput.js';

const router = express.Router();

router.post('/register',validateRegister, registerUser);
router.post('/login',validateLogin, loginUser);
router.get('/me', protect, getMe);
router.get('/admin-only',protect,authorizeRoles('admin'),(req, res) => { 
   res.send('Welcome Admin!');
});
router.post('/logout', logoutUser);
router.get('/refresh', refreshToken);
router.post('/forgot-password', forgotPassword);
router.put('/reset-password/:token', resetPassword);

export default router;
