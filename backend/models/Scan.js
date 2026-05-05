const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema({
  userId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  scanType: { type: String, enum: ['file', 'url', 'network'], required: true },
  target:   { type: String, required: true },

  // ML result — stored as capitalised string, no enum restriction so saves never fail
  verdict:    { type: String, required: true, default: 'Benign' },
  confidence: { type: Number, min: 0, max: 1, default: 0 },
  details:    { type: mongoose.Schema.Types.Mixed, default: {} },
  modelUsed:  { type: String, default: 'hybrid_ae_xgboost' },

  // Extra fields
  fileSize: { type: Number, default: null },
  sha256:   { type: String, default: null },
  domain:   { type: String, default: null },

  processingTime: { type: Number, default: 0 },
  scannedAt:      { type: Date, default: Date.now }
}, { timestamps: true });

scanSchema.index({ userId: 1, scannedAt: -1 });
scanSchema.index({ userId: 1, verdict: 1 });
scanSchema.index({ userId: 1, scanType: 1 });

module.exports = mongoose.model('Scan', scanSchema);