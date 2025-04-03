require("dotenv").config();
import nodemailer, { Transporter } from "nodemailer";
import path from "path";
import ejs from "ejs";

interface EmailOptions {
  email: string;
  subject: string;
  template: string;
  data: { [key: string]: any };
}

const sendmail = async (options: EmailOptions): Promise<void> => {
  console.log("sendmail");
  const transporter: Transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || "587"),
    service: process.env.SMPT_SERVICE,
    auth: {
      user: process.env.SMTP_MAIL,
      pass: process.env.SMTP_PASSWORD,
    },
  });

  const { email, subject, template, data } = options;

  // get the path to email template file

  const templatePath = path.join(__dirname, "../mails", template);

  // render the email template with ejs
  const html: string = await ejs.renderFile(templatePath, data);

  const mailoptions = {
    from: process.env.SMTP_MAIL,
    to: email,
    subject,
    html,   // simple template (.ejs file)
  };
  try {
    await transporter.sendMail(mailoptions);
    console.log("✅ Email Sent Successfully");
  } catch (error: any) {
    console.error("❌ Email Sending Failed:", error.message);
  }
};

export default sendmail;
