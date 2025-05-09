const express = require('express');
const router = express.Router();
const { supabase } = require('../utils/supabaseClient');
const verifyCookieJWT = require('../middleware/verifyCookieJWT');

// GET /api/deals - Fetch all deals
router.get('/', verifyCookieJWT, async (req, res) => {
  const { data, error } = await supabase
    .from('deals_submitted')
    .select('id, business_name, lender_names, creation_date, filename, dealid')
    .order('creation_date', { ascending: false });

  if (error) {
    console.error('Error fetching deals:', error.message);
    return res.status(500).json({ error: error.message });
  }

  res.json(data);
});

module.exports = router;
