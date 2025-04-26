const { verifyToken } = require('../utils/tokenUtils');

function verifyCookieJWT(req, res, next) {
  const token = req.cookies?.token;

  if (!token) return res.status(401).json({ message: 'Missing token in cookies' });

  const decoded = verifyToken(token);
  if (!decoded) return res.status(403).json({ message: 'Invalid token' });

  req.user = decoded;
  next();
}

module.exports = verifyCookieJWT;
