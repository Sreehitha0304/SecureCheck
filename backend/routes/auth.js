const express = require('express');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const User    = require('../models/User');
const auth    = require('../middleware/auth');

const router = express.Router();

/* ─────────────────────────────
   JWT SIGNER
───────────────────────────── */
const signToken = (id) =>
  jwt.sign(
    { userId: id },
    process.env.JWT_SECRET || 'dev_secret',
    { expiresIn: '7d' }
  );

/* ─────────────────────────────
   OTP STORE (IN-MEMORY)
   (FOR PRODUCTION → USE REDIS OR DB)
───────────────────────────── */
const otpStore = new Map(); 
// email -> { otp, expires }

/* ─────────────────────────────
   SIGNUP
───────────────────────────── */
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name?.trim())
      return res.status(400).json({ error: 'Full name is required.' });

    if (!email?.trim())
      return res.status(400).json({ error: 'Email is required.' });

    if (!password || password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    const cleanEmail = email.toLowerCase().trim();

    const exists = await User.findOne({ email: cleanEmail });
    if (exists)
      return res.status(409).json({ error: 'Email already registered.' });

    const user = await User.create({
      name: name.trim(),
      email: cleanEmail,
      password
    });

    const token = signToken(user._id);

    return res.status(201).json({ token, user });
  } catch (e) {
    console.error('[SIGNUP]', e);
    return res.status(500).json({ error: 'Server error during signup.' });
  }
});

/* ─────────────────────────────
   LOGIN
───────────────────────────── */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required.' });

    const cleanEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: cleanEmail });
    if (!user)
      return res.status(404).json({ error: 'User not found.' });

    const ok = await user.comparePassword(password);
    if (!ok)
      return res.status(401).json({ error: 'Invalid password.' });

    user.lastLogin = new Date();
    await user.save();

    const token = signToken(user._id);

    return res.json({ token, user });
  } catch (e) {
    console.error('[LOGIN]', e);
    return res.status(500).json({ error: 'Server error during login.' });
  }
});

/* ─────────────────────────────
   GET ME
───────────────────────────── */
router.get('/me', auth, async (req, res) => {
  return res.json(req.user);
});

/* ─────────────────────────────
   FORGOT PASSWORD (OTP)
───────────────────────────── */
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email)
      return res.status(400).json({ error: 'Email required.' });

    const cleanEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: cleanEmail });
    if (!user)
      return res.status(404).json({ error: 'No account found.' });

    const otp = crypto.randomInt(100000, 999999).toString();
    const expires = Date.now() + 10 * 60 * 1000;

    otpStore.set(cleanEmail, { otp, expires });

    console.log(`[OTP] ${cleanEmail} => ${otp}`);

    return res.json({
      message: 'OTP generated. Check backend console (dev mode).'
    });
  } catch (e) {
    console.error('[FORGOT PASSWORD]', e);
    return res.status(500).json({ error: 'Server error.' });
  }
});

/* ─────────────────────────────
   VERIFY OTP
───────────────────────────── */
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp)
      return res.status(400).json({ error: 'Email and OTP required.' });

    const cleanEmail = email.toLowerCase().trim();

    const record = otpStore.get(cleanEmail);

    if (!record)
      return res.status(400).json({ error: 'OTP not found. Request again.' });

    if (Date.now() > record.expires) {
      otpStore.delete(cleanEmail);
      return res.status(400).json({ error: 'OTP expired.' });
    }

    if (record.otp !== otp.trim())
      return res.status(400).json({ error: 'Invalid OTP.' });

    // secure reset token (short lived concept)
    const resetToken = jwt.sign(
      { email: cleanEmail, purpose: 'reset' },
      process.env.JWT_SECRET || 'dev_secret',
      { expiresIn: '10m' }
    );

    return res.json({
      message: 'OTP verified',
      resetToken
    });
  } catch (e) {
    console.error('[VERIFY OTP]', e);
    return res.status(500).json({ error: 'Server error.' });
  }
});

/* ─────────────────────────────
   RESET PASSWORD
───────────────────────────── */
router.post('/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword)
      return res.status(400).json({ error: 'All fields required.' });

    if (newPassword.length < 8)
      return res.status(400).json({ error: 'Password too short.' });

    const cleanEmail = email.toLowerCase().trim();

    const record = otpStore.get(cleanEmail);

    if (!record || record.otp !== otp.trim() || Date.now() > record.expires) {
      return res.status(400).json({ error: 'Invalid or expired OTP.' });
    }

    const user = await User.findOne({ email: cleanEmail });
    if (!user)
      return res.status(404).json({ error: 'User not found.' });

    user.password = newPassword; // hashed in schema pre-save
    await user.save();

    otpStore.delete(cleanEmail);

    return res.json({ message: 'Password reset successful.' });
  } catch (e) {
    console.error('[RESET PASSWORD]', e);
    return res.status(500).json({ error: 'Server error.' });
  }
});

/* ─────────────────────────────
   CHANGE PASSWORD (LOGGED IN)
───────────────────────────── */
router.post('/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: 'Both fields required.' });

    if (newPassword.length < 8)
      return res.status(400).json({ error: 'Password too short.' });

    const ok = await req.user.comparePassword(currentPassword);
    if (!ok)
      return res.status(401).json({ error: 'Wrong current password.' });

    req.user.password = newPassword;
    await req.user.save();

    return res.json({ message: 'Password updated.' });
  } catch (e) {
    console.error('[CHANGE PASSWORD]', e);
    return res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;