require('dotenv').config(); // MUST be first

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

const app = express();

/* ───────────────── SECURITY ───────────────── */
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

/* ───────────────── CORS ───────────────── */
app.use(cors({
  origin: [
    "https://secure-check-six.vercel.app",
    /\.vercel\.app$/   // allows preview deployments
  ],
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
/* ───────────────── BODY PARSING ───────────────── */
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

/* ───────────────── HEALTH CHECK ───────────────── */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    time: new Date().toISOString()
  });
});

/* ───────────────── API ROUTES ───────────────── */
app.use('/api/auth', require('./routes/auth'));
app.use('/api/dashboard', require('./routes/dashboard'));
app.use('/api/network', require('./routes/network'));
app.use('/api/scan', require('./routes/scan'));

/* ───────────────── STATIC FRONTEND ───────────────── */
app.use(express.static(path.join(__dirname, '../frontend')));

/* ───────────────── FRONTEND FALLBACK ───────────────── */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/auth.html'));
});

/* ───────────────── ERROR HANDLER ───────────────── */
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err);

  res.status(500).json({
    error: process.env.NODE_ENV === 'development'
      ? err.message
      : 'Internal Server Error'
  });
});

/* ───────────────── MONGODB + SERVER START ───────────────── */
mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 15000,
  socketTimeoutMS: 45000
})
.then(() => {
  console.log('✅ MongoDB connected');

  /* 🔥 IMPORTANT FIX (Render-safe PORT) */
const PORT = process.env.PORT || 5000;

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
})
.catch(err => {
  console.error('❌ MongoDB connection failed:', err.message);
  process.exit(1);
});