import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: `smtp.gmail.com`,
  port: 587,
  secure: false,
  auth: {
    user: process.env.COMPANY_EMAIL,
    pass: process.env.COMPANY_EMAIL_PASSWORD,
  },
});


const generateOtp = (length: number = 6) => {
  let otp = ``;
  for (let i = 0; i < length; i++) {
    otp += Math.floor(Math.random() * 10);
  }

  return otp;
};

const sendOtpEmail = async (email: string, otp: number) => {
  
    const mailOption = {
      from: `<${process.env.COMPANY_EMAIL}>`,
      to: email,
      subject: `Password Reset OTP`,
      html: `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p>Hello,</p>
          <p>You requested to reset your password. Use the following OTP to proceed:</p>
          <div style="background-color: #f4f4f4; padding: 15px; border-radius: 5px; text-align: center; margin: 20px 0;">
            <h1 style="color: #4CAF50; font-size: 32px; letter-spacing: 5px; margin: 0;">${otp}</h1>
          </div>
          <p>This OTP will expire in <strong>10 minutes</strong>.</p>
          <p>If you didn't request this, please ignore this email or contact support.</p>
          <hr style="border: 1px solid #eee; margin: 20px 0;">
          <p style="color: #777; font-size: 12px;">For security reasons, never share this OTP with anyone.</p>
        </div>
      `,
      text: `Your OTP for password reset is: ${otp}. This OTP will expire in 10 minutes. 
    ` // this is a fallback 
    };
     
    await transporter.sendMail(mailOption);
 
};

export { generateOtp, sendOtpEmail };
