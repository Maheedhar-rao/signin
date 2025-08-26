const express = require('express');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const verifyCookieJWT = require('./middleware/verifyCookieJWT'); // <-- fix path
require('dotenv').config();

const app = express();

// If behind a proxy / CDN and using secure cookies:
app.set('trust proxy', 1);

app.use(cors({
  origin: [
    'https://croccrm.com',
    'https://login.croccrm.com',
    'https://dashboard.croccrm.com'
  ],
  credentials: true
}));

app.use(cookieParser());
app.use(express.json());

// ---- DO NOT expose the dashboard via static BEFORE the protected route ----
// Serve protected dashboard *before* static to ensure middleware runs:
app.get('/dashboard.html', verifyCookieJWT, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

// (Optional) protect other app pages similarly:
// app.get('/admin.html', verifyCookieJWT, (...));
// app.get('/shopfunder.html', verifyCookieJWT, (...));
// app.get('/verdecredit.html', verifyCookieJWT, (...));

// Public config — ONLY expose anon key
app.get('/config', (req, res) => {
  res.json({
    SUPABASE_URL: process.env.SUPABASE_URL,
    SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY // <- not service role
  });
});

// Now static files (css/js/images) AFTER protected routes:
app.use(express.static(path.join(__dirname, '../public')));

// Root redirect to login
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// Healthcheck (optional)
app.get('/health', (req, res) => res.send('ok'));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Signin service running at http://localhost:${PORT}`);
});
