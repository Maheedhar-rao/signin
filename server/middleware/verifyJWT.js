const { verifyToken } = require('../utils/tokenUtils');

function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Missing token' });

  const decoded = verifyToken(token);
  if (!decoded) return res.status(403).json({ message: 'Invalid token' });

  req.user = decoded;
  next();
}

module.exports = verifyJWT;
