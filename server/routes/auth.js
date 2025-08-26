// routes/auth.js
const express = require('express');
const router = express.Router();
const supabase = require('../utils/supabaseClient');
const { signToken, verifyToken } = require('../utils/tokenUtils');
const verifyCookieJWT = require('../middleware/verifyCookieJWT');
const bcrypt = require('bcrypt');

// Cookie opts helper
function cookieOpts() {
  const isProd = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProd,               // true on HTTPS in prod, false for localhost
    sameSite: isProd ? 'none' : 'lax',
    domain: isProd ? '.croccrm.com' : undefined,
    maxAge: 6 * 60 * 60 * 1000    // 6 hours
  };
}

/**
 * POST /auth/login
 * Body: { email, password }
 * Flow:
 *  1) find user in registered_users
 *  2) check status != disabled
 *  3) compare bcrypt password
 *  4) set HttpOnly JWT cookie
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const { data: user, error: userErr } = await supabase
      .from('registered_users')
      .select('id, email, role, status, password_hash')
      .eq('email', email.toLowerCase())
      .single();

    if (userErr || !user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (user.status === 'disabled') {
      return res.status(403).json({ error: 'Your account has been disabled. Please contact CROC CRM' });
    }

    if (!user.password_hash) {
      return res.status(401).json({ error: 'Password not set for this account' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

    const tokenPayload = { id: user.id, email: user.email, role: user.role || 'user' };
    const token = signToken(tokenPayload);
    res.cookie('token', token, cookieOpts());

    return res.json({ ok: true });
  } catch (err) {
    console.error('POST /auth/login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /auth/logout
 */
router.post('/logout', (req, res) => {
  res.clearCookie('token', cookieOpts());
  res.json({ message: 'Logged out' });
});

/**
 * GET /auth/me
 * Returns decoded JWT payload if present
 */
router.get('/me', (req, res) => {
  const token = req.cookies?.token;
  if (!token) return res.status(401).send('Unauthorized');
  try {
    const decoded = verifyToken(token);
    res.json(decoded);
  } catch {
    res.status(403).send('Invalid token');
  }
});

/**
 * GET /auth/api/users
 * Admin only
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
    res.json(data);
  } catch (err) {
    console.error('GET /auth/api/users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

/**
 * GET /auth/api/deals?userId=...
 * Only allowed if requester is your super admin email
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
    res.json(data);
  } catch (err) {
    console.error('GET /auth/api/deals error:', err);
    res.status(500).json({ error: 'Failed to fetch deals' });
  }
});

/**
 * POST /auth/api/disable-user
 * Body: { userId }
 * Admin only
 */
router.post('/api/disable-user', verifyCookieJWT, async (req, res) => {
  const user = req.user;
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { userId } = req.body;
  try {
    const { error } = await supabase
      .from('registered_users')
      .update({ status: 'disabled' })
      .eq('id', userId);
    if (error) throw error;
    res.json({ message: 'User disabled successfully' });
  } catch (err) {
    console.error('POST /auth/api/disable-user error:', err);
    res.status(500).json({ message: 'Failed to disable user' });
  }
});

module.exports = router;
