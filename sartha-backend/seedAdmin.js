require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

const seedAdmin = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to MongoDB');

        const adminEmail = process.env.EMAIL_USER;

        if (!adminEmail) {
            console.error('Please set EMAIL_USER in your .env file to the email you want to be admin.');
            process.exit(1);
        }

        const user = await User.findOne({ email: adminEmail });

        if (!user) {
            console.error(`User with email ${adminEmail} not found! Please register an account first.`);
            process.exit(1);
        }

        user.role = 'admin';
        user.isVerified = true;
        await user.save();

        console.log(`Success! ${adminEmail} has been granted Admin privileges.`);
        process.exit(0);

    } catch (error) {
        console.error('Error seeding admin:', error);
        process.exit(1);
    }
};

seedAdmin();
