const express = require('express');
const router = express.Router();
const supabase = require('../utils/supabaseClient');
const { signToken, verifyToken } = require('../utils/tokenUtils');
const verifyCookieJWT = require('../middleware/verifyCookieJWT');

const sendEmail = require('../utils/sendEmail');


router.post('/check-email', async (req, res) => {
  const { email } = req.body;

  const { data: user, error } = await supabase
    .from('registered_users')
    .select('id, email')
    .eq('email', email)
    .single();

  if (error || !user) return res.status(401).json({ message: 'Email not found' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();

  await supabase.from('email_codes').insert([{ email, code }]);
  await sendEmail(email, `Your login code is: ${code}`);

  res.json({ message: 'Verification code sent' });
});


router.post('/verify-code', async (req, res) => {
  const { email, code } = req.body;

  const { data: match, error } = await supabase
    .from('email_codes')
    .select('*')
    .eq('email', email)
    .eq('code', code)
    .gt('expires_at', new Date().toISOString())
    .single();

  if (error || !match) return res.status(403).json({ message: 'Invalid or expired code' });

  const { data: user } = await supabase
    .from('registered_users')
    .select('id, email, role')
    .eq('email', email)
    .single();

   if (!user || user.status === 'disabled') {
    return res.status(403).json({ message: 'Your account has been disabled. Please contact CROC CRM' });
  }

  const token = signToken(user);

  res.cookie('token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    domain: '.croccrm.com',
    maxAge: 6 * 60 * 60 * 1000 // 1 hour
  });

  res.json({
    message: 'Login successful',
    email: user.email,
    //role: user.role
  });
});

router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});


router.get('/me', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).send('Unauthorized');

  try {
    const decoded = verifyToken(token);
    res.json(decoded);
  } catch {
    res.status(403).send('Invalid token');
  }
});

router.get('/api/users', verifyCookieJWT, async (req, res) => {
  const user = req.user;
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    const { data, error } = await supabase
      .from('registered_users')
      .select('id, email')
      .order('email');

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

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
    console.error('Error fetching deals:', err);
    res.status(500).json({ error: 'Failed to fetch deals' });
  }
});


module.exports = router;
