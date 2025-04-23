const jwt = require('jsonwebtoken');

const signToken = (user) => {
  return jwt.sign({
    id: user.id,
    email: user.email,
    role: user.role
  }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRY });
};

const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
};

module.exports = { signToken, verifyToken };
