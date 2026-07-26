/**
 * TrustLayer Backend — single-file version for Render deployment.
 *
 * Contains: Express server, Postgres schema bootstrap, JWT auth,
 * signup/login, the heuristic scam analyzer, community reporting,
 * and site stats. No external paid APIs required.
 *
 * Deploy on Render:
 *   1. Create a Postgres database on Render, copy its "Internal Database URL".
 *   2. Create a Web Service pointing at this file's repo.
 *      Build command:  npm install
 *      Start command:  node server.js
 *   3. Set env vars on the web service:
 *        DATABASE_URL = <the Postgres connection string>
 *        JWT_SECRET   = any long random string
 *        CORS_ORIGIN  = your frontend URL (or * while testing)
 *   4. Deploy. You'll get a URL like https://<name>.onrender.com
 *
 * Requires package.json with dependencies:
 *   express, cors, express-rate-limit, pg, bcryptjs, jsonwebtoken, dotenv
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

/* ============================================================
   Database
   ============================================================ */

const connectionString = process.env.DATABASE_URL;

const pool = new Pool({
  connectionString,
  ssl: connectionString && connectionString.includes('render.com')
    ? { rejectUnauthorized: false }
    : (process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false),
});

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  account_type TEXT NOT NULL DEFAULT 'individual',
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  dial_code TEXT,
  phone_number TEXT,
  country TEXT,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  input_text TEXT NOT NULL,
  score INTEGER NOT NULL,
  risk_level TEXT NOT NULL,
  flags JSONB NOT NULL DEFAULT '[]',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reports (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  reporter_name TEXT,
  category TEXT NOT NULL DEFAULT 'other',
  description TEXT NOT NULL,
  target TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports (created_at DESC);
`;

async function initSchema() {
  await pool.query(SCHEMA_SQL);
}

/* ============================================================
   Auth helpers (JWT)
   ============================================================ */

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing authorization token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.sub, email: payload.email };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function optionalAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return next();
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.sub, email: payload.email };
  } catch (err) {
    // ignore invalid token for optional auth
  }
  next();
}

/* ============================================================
   Scam-risk heuristic engine
   ============================================================ */

const URL_REGEX = /\b((?:https?:\/\/|www\.)[^\s<>"')]+)/gi;
const IP_HOST_REGEX = /^(?:https?:\/\/)?(\d{1,3}\.){3}\d{1,3}/i;
const SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorte.st', 'adf.ly', 'bl.ink',
];
const RISKY_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.icu', '.club', '.work', '.info'];

const KEYWORD_GROUPS = [
  { weight: 18, label: 'urgency / pressure tactics', words: ['act now', 'urgent', 'immediately', 'expires today', 'limited time', 'final notice', 'last chance', 'within 24 hours', 'act fast'] },
  { weight: 22, label: 'unrealistic financial promises', words: ['guaranteed return', 'guaranteed profit', 'double your money', 'risk-free', 'risk free', '100% profit', 'no risk', 'guaranteed income', 'passive income guaranteed'] },
  { weight: 20, label: 'payment red flags', words: ['gift card', 'itunes card', 'google play card', 'wire transfer', 'western union', 'moneygram', 'send money', 'crypto wallet', 'bitcoin wallet', 'processing fee', 'advance fee', 'release fee', 'clearance fee'] },
  { weight: 20, label: 'account / identity threats', words: ['verify your account', 'account suspended', 'account has been locked', 'confirm your identity', 'unusual activity', 'unauthorized access', 'update your payment details', 'your account will be closed'] },
  { weight: 16, label: 'too-good-to-be-true offers', words: ['you have won', "you've won", 'claim your prize', 'lottery', 'inheritance', 'free iphone', 'congratulations you', 'selected as a winner'] },
  { weight: 14, label: 'secrecy / isolation requests', words: ["don't tell anyone", 'keep this confidential', 'between us', 'do not share this'] },
  { weight: 12, label: 'romance / relationship manipulation', words: ['i love you', 'my darling', 'we are meant to be', 'i need money for my visa', 'stuck at customs'] },
];

function extractUrls(text) {
  return (text.match(URL_REGEX) || []).map((u) => u.trim());
}

function analyzeUrl(url) {
  const flags = [];
  let score = 0;
  let host = url.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();

  if (IP_HOST_REGEX.test(url)) {
    score += 25;
    flags.push(`Link uses a raw IP address instead of a domain (${host})`);
  }
  if (SHORTENERS.some((s) => host.includes(s))) {
    score += 15;
    flags.push(`Link uses a URL shortener (${host}), which hides the real destination`);
  }
  if (RISKY_TLDS.some((tld) => host.endsWith(tld))) {
    score += 12;
    flags.push(`Link uses a domain extension frequently abused for scams (${host})`);
  }
  if (/xn--/i.test(host)) {
    score += 20;
    flags.push('Link uses punycode / lookalike characters, common in phishing');
  }
  if (!/^https:/i.test(url) && /^http:/i.test(url)) {
    score += 8;
    flags.push('Link is not using a secure (https) connection');
  }
  const hyphenCount = (host.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 8;
    flags.push('Domain contains many hyphens, a pattern often used to impersonate brands');
  }
  return { score, flags };
}

function detectPhoneNumbers(text) {
  const matches = text.match(/(\+?\d[\d\-\s().]{7,}\d)/g) || [];
  return matches.map((m) => m.trim());
}

function analyzeText(rawInput) {
  const text = String(rawInput || '');
  const lower = text.toLowerCase();

  let score = 0;
  const flags = [];

  for (const group of KEYWORD_GROUPS) {
    const hit = group.words.find((w) => lower.includes(w));
    if (hit) {
      score += group.weight;
      flags.push(`Contains language consistent with ${group.label} ("${hit}")`);
    }
  }

  const urls = extractUrls(text);
  for (const url of urls.slice(0, 5)) {
    const result = analyzeUrl(url);
    score += result.score;
    flags.push(...result.flags);
  }

  const phones = detectPhoneNumbers(text);
  if (phones.length > 0 && (lower.includes('call') || lower.includes('text'))) {
    score += 6;
    flags.push('Includes a phone number paired with a call-to-action, common in vishing/smishing');
  }

  const words = text.split(/\s+/).filter((w) => w.length > 3);
  const capsWords = words.filter((w) => w === w.toUpperCase() && /[A-Z]/.test(w));
  if (words.length > 0 && capsWords.length / words.length > 0.3) {
    score += 6;
    flags.push('Excessive capitalization, often used to create false urgency');
  }

  if (/[!?]{3,}/.test(text)) {
    score += 4;
    flags.push('Excessive punctuation (e.g. "!!!"), a common manipulation pattern');
  }

  if (/(password|ssn|social security|pin code|otp|one[- ]time password|card number|cvv)/i.test(text)) {
    score += 22;
    flags.push('Directly requests sensitive personal or financial information');
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  let riskLevel = 'low';
  if (score >= 60) riskLevel = 'high';
  else if (score >= 30) riskLevel = 'medium';

  if (flags.length === 0) {
    flags.push('No known scam patterns detected in this heuristic scan');
  }

  return { score, riskLevel, flags: [...new Set(flags)], urlsFound: urls, phonesFound: phones };
}

/* ============================================================
   Express app
   ============================================================ */

const app = express();
const PORT = process.env.PORT || 3000;

const allowedOrigins = (process.env.CORS_ORIGIN || '*')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(cors({ origin: allowedOrigins.includes('*') ? true : allowedOrigins }));
app.use(express.json({ limit: '200kb' }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'trustlayer-backend' });
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'error', db: 'unavailable' });
  }
});

/* ---------- Auth routes ---------- */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const authRouter = express.Router();

authRouter.post('/signup', async (req, res) => {
  try {
    const {
      accountType = 'individual', fullName, email, dialCode, phoneNumber, country, password,
    } = req.body || {};

    if (!fullName || String(fullName).trim().length < 2) {
      return res.status(400).json({ error: 'Name must be at least 2 characters' });
    }
    if (!email || !EMAIL_RE.test(String(email).trim())) {
      return res.status(400).json({ error: 'A valid email is required' });
    }
    if (!phoneNumber || String(phoneNumber).replace(/\D/g, '').length < 6) {
      return res.status(400).json({ error: 'A valid phone number is required' });
    }
    if (!country) {
      return res.status(400).json({ error: 'Country is required' });
    }
    if (!password || String(password).length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(String(password), 10);
    const result = await pool.query(
      `INSERT INTO users (account_type, full_name, email, dial_code, phone_number, country, password_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, account_type, full_name, email, country, created_at`,
      [accountType, String(fullName).trim(), normalizedEmail, dialCode || null, String(phoneNumber).trim(), country, passwordHash]
    );

    const user = result.rows[0];
    const token = signToken(user);

    return res.status(201).json({
      token,
      user: { id: user.id, accountType: user.account_type, fullName: user.full_name, email: user.email, country: user.country },
    });
  } catch (err) {
    console.error('signup error', err);
    return res.status(500).json({ error: 'Something went wrong creating your account' });
  }
});

authRouter.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const normalizedEmail = String(email).trim().toLowerCase();
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const ok = await bcrypt.compare(String(password), user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

    const token = signToken(user);
    return res.json({
      token,
      user: { id: user.id, accountType: user.account_type, fullName: user.full_name, email: user.email, country: user.country },
    });
  } catch (err) {
    console.error('login error', err);
    return res.status(500).json({ error: 'Something went wrong logging you in' });
  }
});

authRouter.get('/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, account_type, full_name, email, country, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json({
      user: {
        id: user.id, accountType: user.account_type, fullName: user.full_name,
        email: user.email, country: user.country, createdAt: user.created_at,
      },
    });
  } catch (err) {
    console.error('me error', err);
    return res.status(500).json({ error: 'Something went wrong' });
  }
});

app.use('/api/auth', authRouter);

/* ---------- Analyzer route ---------- */

const analyzeRouter = express.Router();

analyzeRouter.post('/', optionalAuth, async (req, res) => {
  try {
    const { input } = req.body || {};
    if (!input || !String(input).trim()) {
      return res.status(400).json({ error: 'Please provide text, a link, or a message to analyze' });
    }

    const text = String(input).slice(0, 5000);
    const result = analyzeText(text);
    const userId = req.user ? req.user.id : null;

    const inserted = await pool.query(
      `INSERT INTO scans (user_id, input_text, score, risk_level, flags)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, created_at`,
      [userId, text, result.score, result.riskLevel, JSON.stringify(result.flags)]
    );

    return res.json({
      id: inserted.rows[0].id,
      createdAt: inserted.rows[0].created_at,
      score: result.score,
      riskLevel: result.riskLevel,
      flags: result.flags,
      urlsFound: result.urlsFound,
      phonesFound: result.phonesFound,
    });
  } catch (err) {
    console.error('analyze error', err);
    return res.status(500).json({ error: 'Something went wrong analyzing that input' });
  }
});

app.use('/api/analyze', analyzeRouter);

/* ---------- Community reporting routes ---------- */

const CATEGORIES = new Set(['phishing', 'investment', 'romance', 'impersonation', 'lottery', 'tech-support', 'other']);
const reportsRouter = express.Router();

reportsRouter.post('/', optionalAuth, async (req, res) => {
  try {
    const { category = 'other', description, target, reporterName } = req.body || {};
    if (!description || String(description).trim().length < 10) {
      return res.status(400).json({ error: 'Please describe the scam in at least 10 characters' });
    }
    const normalizedCategory = CATEGORIES.has(category) ? category : 'other';
    const userId = req.user ? req.user.id : null;

    const result = await pool.query(
      `INSERT INTO reports (user_id, reporter_name, category, description, target)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, category, description, target, status, created_at`,
      [userId, reporterName || null, normalizedCategory, String(description).trim(), target || null]
    );

    return res.status(201).json({ report: result.rows[0] });
  } catch (err) {
    console.error('create report error', err);
    return res.status(500).json({ error: 'Something went wrong submitting your report' });
  }
});

reportsRouter.get('/', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
    const result = await pool.query(
      `SELECT id, category, description, target, status, created_at
       FROM reports ORDER BY created_at DESC LIMIT $1`,
      [limit]
    );
    return res.json({ reports: result.rows });
  } catch (err) {
    console.error('list reports error', err);
    return res.status(500).json({ error: 'Something went wrong fetching reports' });
  }
});

app.use('/api/reports', reportsRouter);

/* ---------- Stats route ---------- */

const statsRouter = express.Router();

statsRouter.get('/', async (req, res) => {
  try {
    const [scansCount, highRiskCount, reportsCount, usersCount] = await Promise.all([
      pool.query('SELECT COUNT(*)::int AS n FROM scans'),
      pool.query("SELECT COUNT(*)::int AS n FROM scans WHERE risk_level = 'high'"),
      pool.query('SELECT COUNT(*)::int AS n FROM reports'),
      pool.query('SELECT COUNT(*)::int AS n FROM users'),
    ]);

    return res.json({
      totalScans: scansCount.rows[0].n,
      highRiskScans: highRiskCount.rows[0].n,
      totalReports: reportsCount.rows[0].n,
      totalUsers: usersCount.rows[0].n,
    });
  } catch (err) {
    console.error('stats error', err);
    return res.status(500).json({ error: 'Something went wrong fetching stats' });
  }
});

app.use('/api/stats', statsRouter);

/* ---------- Fallbacks ---------- */

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error', err);
  res.status(500).json({ error: 'Internal server error' });
});

/* ============================================================
   Startup
   ============================================================ */

async function start() {
  try {
    await initSchema();
    console.log('Database schema ready');
  } catch (err) {
    console.error('Failed to initialize database schema', err);
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`TrustLayer backend listening on port ${PORT}`);
  });
}

start();
