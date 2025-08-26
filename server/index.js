const express = require('express');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth');
const verifyCookieJWT = require('./middleware/verifyCookieJWT');

require('dotenv').config();

const app = express();

// behind proxy/CDN with secure cookies
app.set('trust proxy', 1);

app.use(cors({
  origin: [
    'https://croccrm.com',
    'https://login.croccrm.com',
    'https://dashboard.croccrm.com',
    'http://localhost:3000'
  ],
  credentials: true
}));

app.use(cookieParser());
app.use(express.json());

// Protected HTML pages FIRST (so static can't bypass)
app.get('/dashboard.html', verifyCookieJWT, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});
app.get('/admin.html', verifyCookieJWT, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin.html'));
});
app.get('/shopfunder.html', verifyCookieJWT, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/shopfunder.html'));
});
app.get('/verdecredit.html', verifyCookieJWT, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/verdecredit.html'));
});

// Static assets AFTER protected routes
app.use(express.static(path.join(__dirname, '../public')));

// Auth routes
app.use('/auth', authRoutes);

// Optional: expose only anon key if you really need it client-side
app.get('/config', (req, res) => {
  res.json({
    SUPABASE_URL: process.env.SUPABASE_URL,
    SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY
  });
});

// Root -> login
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// Health
app.get('/health', (req, res) => res.send('ok'));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Signin service running at http://localhost:${PORT}`);
});
