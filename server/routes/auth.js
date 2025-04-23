const express = require('express');
const router = express.Router();
const supabase = require('../utils/supabaseClient');
const { signToken } = require('../utils/tokenUtils');

// Step 1: Check email exists
router.post('/check-email', async (req, res) => {
  const { email } = req.body;
  const { data, error } = await supabase
    .from('registered_users')
    .select('id, email, role')
    .eq('email', email)
    .single();

  if (error || !data) return res.status(401).json({ message: 'Email not registered' });
  res.json({ message: 'Email OK' });
});

// Step 2: Simulated code check + JWT (replace this with real logic)
router.post('/verify-code', async (req, res) => {
  const { email, code } = req.body;

  if (code !== '123456') return res.status(403).json({ message: 'Invalid code' });

  const { data: user, error } = await supabase
    .from('registered_users')
    .select('id, email, role')
    .eq('email', email)
    .single();

  if (error || !user) return res.status(403).json({ message: 'User not found' });

  const token = signToken(user);
  res.json({ message: 'Login successful', token });
});

module.exports = router;
