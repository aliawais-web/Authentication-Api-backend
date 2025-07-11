import asyncHandler from 'express-async-handler';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { User } from '../models/user.js';
import { sendEmail } from '../utils/sendEmail.js';

// @desc    Register user
export const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password, role } = req.body;

  const userExists = await User.findOne({ email });
  if (userExists) {
    res.status(400);
    throw new Error('User already exists');
  }

  const user = await User.create({ name, email, password, role });

  const token = generateToken(user._id);

  res.status(201).json({
    _id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    token
  });
});

// @desc    Login user

export const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user || !(await user.matchPassword(password))) {
    res.status(401);
    throw new Error('Invalid email or password');
  }

  const token = generateToken(user._id); // Access token
  const refresh = generateRefreshToken(user._id); // Refresh token

  res
    .cookie('refreshToken', refresh, {
      httpOnly: true,
      sameSite: 'strict',
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })
    .json({
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      token,
    });
});


// @desc    Get current user profile
export const getMe = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id).select('-password');
  res.json(user);
});

// Generate JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
  });
};

// Generate refresh token
const generateRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '7d',
  });
};

// @desc Refresh access token
export const refreshToken = asyncHandler(async (req, res) => {
  const token = req.cookies.refreshToken;

  if (!token) {
    res.status(401);
    throw new Error('No refresh token found');
  }

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.id);

    const newAccessToken = generateToken(user._id);

    res.json({ token: newAccessToken });
  } catch (error) {
    res.status(401);
    throw new Error('Invalid refresh token');
  }
});

// @desc Logout
export const logoutUser = asyncHandler(async (req, res) => {
  res.clearCookie('refreshToken', {
    httpOnly: true,
    sameSite: 'strict',
    secure: false, // change to true in production
  });

  res.json({ message: 'Logged out successfully' });
});


// @desc Forgot Password
export const forgotPassword = asyncHandler(async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  const resetToken = user.generateResetToken();
  await user.save();

  const resetUrl = `http://localhost:5000/api/auth/reset-password/${resetToken}`;

  await sendEmail({
    to: user.email,
    subject: 'Password Reset',
    text: `Reset your password using this link: ${resetUrl}`,
  });

  res.json({ message: 'Reset email sent' });
});

// @desc Reset Password
export const resetPassword = asyncHandler(async (req, res) => {
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    resetPasswordToken: hashedToken,
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user) {
    res.status(400);
    throw new Error('Invalid or expired token');
  }

  user.password = req.body.password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;
  await user.save();

  res.json({ message: 'Password reset successful' });
});
