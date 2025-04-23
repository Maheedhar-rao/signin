const express = require('express');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth');

require('dotenv').config();
const app = express();

// Enable CORS for cookie-based auth
app.use(cors({ origin: true, credentials: true }));

// Parse cookies from client
app.use(cookieParser());
app.use(express.json());

// Serve static files like login.html, verify.html, dashboard.html
app.use(express.static(path.join(__dirname, '../public')));

// Mount auth routes
app.use('/auth', authRoutes);

// Redirect root to login
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Signin service running at http://localhost:${PORT}`);
});
