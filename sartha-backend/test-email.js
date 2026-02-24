require('dotenv').config();
const sendEmail = require('./utils/email');

async function test() {
    try {
        console.log("Attempting to send email with user:", process.env.EMAIL_USER);
        await sendEmail({
            email: 'lavishchouhan56@gmail.com',
            subject: 'Test Email',
            message: 'This is a test email from your local server.'
        });
        console.log("SUCCESS");
    } catch (e) {
        console.error("Test Error:");
        console.error(e);
    }
}

test();
