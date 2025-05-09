const express = require('express');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth');
const verifyCookieJWT = require('../server/middleware/verifyCookieJWT');
const dealsRoute = require('./routes/deals');


app.use('/api/deals', dealsRoute);

require('dotenv').config();
const app = express();

app.use(cors({
  origin: ['https://croccrm.com', 'https://login.croccrm.com'],  
  credentials: true
}));


app.use(cookieParser());
app.use(express.json());


app.use(express.static(path.join(__dirname, '../public')));

app.use('/auth', authRoutes);


app.get('/dashboard.html', verifyCookieJWT, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});


app.get('/', (req, res) => {
  res.redirect('/login.html');
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Signin service running at http://localhost:${PORT}`);
});
