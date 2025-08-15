require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const fetch = global.fetch || ((...args)=>import('node-fetch').then(({default: f})=>f(...args)));

const app = express();
app.use(helmet());
app.use(cors({ origin: true }));
app.use(express.json({ limit: '1mb' }));
app.use(rateLimit({ windowMs: 10*60*1000, max: 800 }));

// Pass-through lookup to dashboard service
app.post('/api/lookup', async (req, res) => {
  try {
    const r = await fetch(`${process.env.DASHBOARD_BASE_URL}/api/lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body || {})
    });
    const data = await r.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Serve existing site files without modification
app.use(express.static(__dirname, { extensions: ['html'] }));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log('rajhi backend running on', PORT));
