const express = require('express');
//const bcrypt = require('bcrypt');
const router = express.Router();

const supabase = require('../utils/supabaseClient');
const { signToken, verifyToken } = require('../utils/tokenUtils');
const verifyCookieJWT = require('../middleware/verifyCookieJWT');

// cookie options
function cookieOpts() {
  const isProd = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    domain: isProd ? '.croccrm.com' : undefined,
    maxAge: 6 * 60 * 60 * 1000 // 6 hours
  };
}

/**
 * POST /auth/login
 * Body: { email, password }
 */
router.post('/login', async (req, res) => {
  try {
    const emailNorm = (req.body?.email || '').trim();
    const passNorm  = (req.body?.password || '').trim();

    if (!emailNorm || !passNorm) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    console.log('LOGIN attempt ->', emailNorm);

    const { data: user, error: userErr } = await supabase
      .from('registered_users')
      .select('id, email, role, status, password')
      .ilike('email', emailNorm)   // case-insensitive match
      .single();                   // if multiple rows exist, this will error

    if (userErr || !user) {
      console.log('LOGIN fail: user not found or query error:', userErr);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if ((user.status || '').toLowerCase() !== 'active') {
      console.log('LOGIN fail: user status not active:', user.status);
      return res.status(403).json({ error: 'Your account has been disabled. Please contact CROC CRM' });
    }

    const dbPass = (user.password || '').trim();
    if (dbPass !== passNorm) {
      console.log('LOGIN fail: bad password', { got: passNorm, dbLen: dbPass.length });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = signToken({ id: user.id, email: user.email, role: user.role || 'user' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      domain: process.env.NODE_ENV === 'production' ? '.croccrm.com' : undefined,
      maxAge: 6 * 60 * 60 * 1000
    });

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
 * Returns decoded JWT payload
 */
router.get('/me', (req, res) => {
  const token = req.cookies && req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = verifyToken(token);
    res.json(decoded);
  } catch {
    res.status(403).json({ error: 'Invalid token' });
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
    res.json(data);
  } catch (err) {
    console.error('GET /auth/api/users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

/**
 * GET /auth/api/deals?userId=... (super admin email only)
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
 * POST /auth/api/disable-user  Body: { userId } (admin only)
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
