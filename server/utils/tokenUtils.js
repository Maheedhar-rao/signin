const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  console.warn('WARNING: JWT_SECRET is not set');
}

function signToken(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: '6h' });
}

function verifyToken(token) {
  return jwt.verify(token, SECRET);
}

module.exports = { signToken, verifyToken };
