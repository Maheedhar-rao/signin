const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function sendEmail(to, message) {
  await transporter.sendMail({
    from: `"CROC CRM - " <${process.env.EMAIL_FROM}>`,
    to,
    subject: 'Your Login Verification Code',
    text: message
  });
}

module.exports = sendEmail;
