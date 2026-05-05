const router = require('express').Router();
const auth   = require('../middleware/auth');
const Scan   = require('../models/Scan');

router.get('/stats', auth, async (req, res) => {
  try {
    const uid = req.userId;

    const [total, malCount, benCount, byType, recentScans, daily] = await Promise.all([
      Scan.countDocuments({ userId: uid }),
      Scan.countDocuments({ userId: uid, verdict: 'Malicious' }),
      Scan.countDocuments({ userId: uid, verdict: 'Benign' }),
      Scan.aggregate([
        { $match: { userId: uid } },
        { $group: { _id: '$scanType', count: { $sum: 1 } } }
      ]),
      Scan.find({ userId: uid }).sort({ scannedAt: -1 }).limit(15).lean(),
      (async () => {
        const days = [];
        const now = new Date();
        for (let i = 13; i >= 0; i--) {
          const d = new Date(now);
          d.setDate(d.getDate() - i);
          const start = new Date(d.getFullYear(), d.getMonth(), d.getDate());
          const end   = new Date(start); end.setDate(end.getDate() + 1);
          const [tot, mal] = await Promise.all([
            Scan.countDocuments({ userId: uid, scannedAt: { $gte: start, $lt: end } }),
            Scan.countDocuments({ userId: uid, scannedAt: { $gte: start, $lt: end }, verdict: 'Malicious' })
          ]);
          days.push({
            date:      d.toLocaleDateString('en', { month: 'short', day: 'numeric' }),
            total:     tot,
            malicious: mal,
            benign:    tot - mal
          });
        }
        return days;
      })()
    ]);

    const byTypeMap = {};
    byType.forEach(t => { byTypeMap[t._id] = t.count; });

    /* map recent scans to dashboard shape */
    const recent = recentScans.map(s => ({
      _id:        s._id,
      type:       s.scanType,
      verdict:    s.verdict,
      confidence: s.confidence,
      fileName:   s.scanType === 'file' ? s.target : undefined,
      url:        s.scanType !== 'file' ? s.target : undefined,
      domain:     s.domain,
      sha256:     s.sha256,
      fileSize:   s.fileSize,
      scannedAt:  s.scannedAt
    }));

    return res.json({
      totalScans:       total,
      maliciousCount:   malCount,
      benignCount:      benCount,
      maliciousPercent: total ? Math.round(malCount / total * 100) : 0,
      byType:           { file: byTypeMap.file || 0, url: byTypeMap.url || 0, network: byTypeMap.network || 0 },
      recentScans:      recent,
      dailyStats:       daily
    });
  } catch(e) {
    console.error('Stats error:', e);
    return res.status(500).json({ error: 'Failed to load stats.' });
  }
});

module.exports = router;