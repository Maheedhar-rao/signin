const express = require('express');
const path = require('path');
const cors = require('cors');
const authRoutes = require('./routes/auth');

const app = express();
require('dotenv').config();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));
app.use('/auth', authRoutes);

const PORT = process.env.PORT || 4000;
app.get('/', (req, res) => {
  res.redirect('/login.html');
});
app.listen(PORT, () => {
  console.log(`Signin service running on http://localhost:${PORT}`);
});
