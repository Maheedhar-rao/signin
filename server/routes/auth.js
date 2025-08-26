// server/routes/auth.js
const express = require('express');
const router = express.Router();

const supabase = require('../utils/supabaseClient');
const { signToken, verifyToken } = require('../utils/tokenUtils');
const verifyCookieJWT = require('../middleware/verifyCookieJWT');

/** Cookie options used for BOTH set and clear. MUST MATCH EXACTLY. */
function cookieOpts() {
  const isProd = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProd,                         // true on HTTPS in prod
    sameSite: isProd ? 'none' : 'lax',      // cross-site cookie for subdomains
    domain: isProd ? '.croccrm.com' : undefined,
    path: '/',                               // IMPORTANT: must match when clearing
    maxAge: 6 * 60 * 60 * 1000               // 6 hours
  };
}

/**
 * POST /auth/login
 * Body: { email, password }
 * Plain-text password compare against public.registered_users.password
 * (Suitable for internal/testing. NOT secure for public apps.)
 */
router.post('/login', async (req, res) => {
  try {
    const emailNorm = (req.body?.email || '').trim();
    const passNorm  = (req.body?.password || '').trim();

    if (!emailNorm || !passNorm) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const { data: user, error: userErr } = await supabase
      .from('registered_users')
      .select('id, email, role, status, password')
      .ilike('email', emailNorm)    // case-insensitive
      .single();

    if (userErr || !user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if ((user.status || '').toLowerCase() !== 'active') {
      return res.status(403).json({ error: 'Your account has been disabled. Please contact CROC CRM' });
    }

    const dbPass = (user.password || '').trim();
    if (dbPass !== passNorm) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = signToken({
      id: user.id,
      email: user.email,
      role: user.role || 'user'
    });

    res.cookie('token', token, cookieOpts());
    return res.json({ ok: true });
  } catch (err) {
    console.error('POST /auth/login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /auth/logout
 * Clears the cookie using EXACT SAME OPTIONS as set.
 */
router.post('/logout', (req, res) => {
  const opts = cookieOpts();
  res.clearCookie('token', opts);                 // primary clear
  res.cookie('token', '', { ...opts, maxAge: 0 }); // extra safety
  return res.json({ message: 'Logged out' });
});

/**
 * GET /auth/me
 * Returns decoded JWT payload if cookie exists and is valid.
 */
router.get('/me', (req, res) => {
  const token = req.cookies && req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = verifyToken(token); // { id, email, role, iat, exp }
    return res.json(decoded);
  } catch {
    return res.status(403).json({ error: 'Invalid token' });
  }
});

/**
 * GET /auth/api/users  (admin only)
 */
router.get('/api/users', verifyCookieJWT, async (req, res) => {
  const user = req.user;
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const { data, error } = await supabase
      .from('registered_users')
      .select('id, email, status')
      .order('email');
    if (error) throw error;
    return res.json(data);
  } catch (err) {
    console.error('GET /auth/api/users error:', err);
    return res.status(500).json({ error: 'Failed to fetch users' });
  }
});

/**
 * GET /auth/api/deals?userId=...  (locked to super admin email)
 */
router.get('/api/deals', verifyCookieJWT, async (req, res) => {
  const user = req.user;
  const { userId } = req.query;

  if (user.email !== 'govadamaheedhar@gmail.com') {
    return res.status(403).json({ error: 'Access denied' });
  }
  if (!userId) {
    return res.status(400).json({ error: 'Missing userId' });
  }

  try {
    const { data, error } = await supabase
      .from('deals_submitted')
      .select('*')
      .eq('user_id', userId);
    if (error) throw error;
    return res.json(data);
  } catch (err) {
    console.error('GET /auth/api/deals error:', err);
    return res.status(500).json({ error: 'Failed to fetch deals' });
  }
});

/**
 * POST /auth/api/disable-user
 * Body: { userId }  (admin only)
 */
router.post('/api/disable-user', verifyCookieJWT, async (req, res) => {
  const user = req.user;
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }

  const { userId } = req.body;
  if (!userId) return res.status(400).json({ message: 'Missing userId' });

  try {
    const { error } = await supabase
      .from('registered_users')
      .update({ status: 'disabled' })
      .eq('id', userId);
    if (error) throw error;
    return res.json({ message: 'User disabled successfully' });
  } catch (err) {
    console.error('POST /auth/api/disable-user error:', err);
    return res.status(500).json({ message: 'Failed to disable user' });
  }
});

module.exports = router;
