const nodemailer = require("nodemailer");

// Function to send email using Nodemailer
const sendEmail = async ({ to, sender, subject, html, attachments, text }) => {
  try {
    // Create a transporter object using SMTP transport
    let transporter = nodemailer.createTransport({
      service: "Gmail", // Assuming you're using Gmail as the email service provider
      auth: {
        user: "your_email@gmail.com", // your email
        pass: "mom.2408", // your password or app password
      },
    });

    const from = sender || "mortadhaksontini22@gmail.com"; // Use provided sender or default sender

    // Email options
    let mailOptions = {
      from: from,
      to: to,
      subject: subject,
      html: html,
      attachments: attachments, // Attachments, if any
      // text: text, // You can include plain text content if needed
    };

    // Send email
    return transporter.sendMail(mailOptions);
  } catch (error) {
    console.error("Error occurred while sending email:", error);
    throw error; // Propagate the error for handling at the calling end
  }
};
exports.sendEmail = async (args) => {
  if (!process.env.NODE_ENV === "development") {
    return Promise.resolve();
  } else {
    return sendEmail(args);
  }
};
