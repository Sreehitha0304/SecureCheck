require('dotenv').config();  // MUST be first

const express   = require('express');
const mongoose  = require('mongoose');
const cors      = require('cors');
const helmet    = require('helmet');
const path      = require('path');

const app = express();

/* ── Security ── */
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin: '*',   // allow all origins for dev — tighten in production
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));

/* ── Body parsing ── */
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

/* ── Routes ── */
app.use('/api/auth',      require('./routes/auth'));
app.use('/api/scan',      require('./routes/scan'));
app.use('/api/dashboard', require('./routes/dashboard'));
app.use('/api/network',   require('./routes/network'));

/* ── Health ── */
app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

/* ── Serve frontend ── */
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../frontend/pages/auth.html')));

/* ── Global error ── */
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({
    error: process.env.NODE_ENV === 'development' ? err.message : 'Server error'
  });
});

/* ══════════════════════════════════════
   Connect MongoDB then start
   ══════════════════════════════════════ */
mongoose.connect(process.env.MONGO_URI, {   // 🔥 FIXED HERE
  serverSelectionTimeoutMS: 15000,
  socketTimeoutMS: 45000
})
.then(() => {
  console.log('✅ MongoDB connected — db:', mongoose.connection.db.databaseName);

  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`🚀 Backend running at http://localhost:${PORT}`);
    console.log(`🔗 ML service expected at ${process.env.ML_SERVICE_URL}`);
  });
})
.catch(err => {
  console.error('❌ MongoDB connection failed:', err.message);
  process.exit(1);
});