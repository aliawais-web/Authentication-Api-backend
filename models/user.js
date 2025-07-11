import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

const userSchema = new mongoose.Schema({
  name:{
    type:String,
    required: true
},
  email: {
    type: String,
    required: true,
    unique: true
},
  password: { 
    type: String,
    required: true
 },
 resetPasswordToken: String,
 resetPasswordExpire: Date,
  role: {
    type: String,
     enum: ['user', 'admin'], default: 'user' }
},{timestamps: true});


userSchema.methods.generateResetToken = function () {
  const resetToken = crypto.randomBytes(20).toString('hex');

  this.resetPasswordToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 mins

  return resetToken;
};



// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Match user entered password to hashed password
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};



export const User = mongoose.model('User', userSchema);


