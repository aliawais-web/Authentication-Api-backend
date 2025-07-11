import nodemailer from 'nodemailer';

export const sendEmail = async (options) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail', // or your email service
    auth: {
      user: process.env.EMAIL_USER,   // your Gmail address
      pass: process.env.EMAIL_PASS,   // your Gmail app password
    },
    tls: {
      rejectUnauthorized: false, // ✅ This fixes self-signed cert error
    },
  });

  const mailOptions = {
    from: '"Job Portal" <no-reply@example.com>',
    to: options.email,
    subject: options.subject,
    text: options.message,
  };

  await transporter.sendMail(mailOptions);
};

