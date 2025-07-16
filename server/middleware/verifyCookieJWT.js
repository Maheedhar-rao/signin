const supabase = require('../utils/supabaseClient');
const { verifyToken } = require('../utils/tokenUtils');

async function verifyCookieJWT(req, res, next) {
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).json({ message: 'Missing token in cookies' });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(403).json({ message: 'Invalid token' });
  }

  const { data: userData, error } = await supabase
    .from('registered_users')
    .select('status')
    .eq('id', decoded.id)
    .single();

  if (error || !userData || userData.status === 'disabled') {
    return res.status(403).json({ message: 'Your account has been disabled' });
  }

  req.user = decoded;
  next();
}

module.exports = verifyCookieJWT;
