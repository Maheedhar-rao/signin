const { verifyToken } = require('../utils/tokenUtils');

module.exports = function verifyCookieJWT(req, res, next) {
  const token = req.cookies && req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = verifyToken(token); // { id, email, role, iat, exp }
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};
