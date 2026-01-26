import React from 'react';
import { motion } from 'framer-motion';

const CTAButton = ({ text, onClick }) => {
    return (
        <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="bg-blue-600 text-white px-6 py-2 rounded-full font-bold hover:bg-blue-700 transition"
            onClick={onClick}
        >
            {text}
        </motion.button>
    );
};

export default CTAButton;
