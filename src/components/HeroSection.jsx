import React from 'react';
import { motion } from 'framer-motion';
import { FaCheckCircle, FaStar } from 'react-icons/fa';

const HeroSection = () => {
    return (
        <div className="relative bg-[#F9FAFB] pt-24 pb-32 min-h-[85vh] overflow-hidden flex items-center">
            {/* Dynamic Background Elements */}
            <div className="absolute inset-0 pointer-events-none">
                <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-purple-200 rounded-full blur-[100px] opacity-30 animate-pulse"></div>
                <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-pink-200 rounded-full blur-[100px] opacity-30 animate-pulse delay-700"></div>
                <div className="absolute inset-0 opacity-[0.03]" style={{ backgroundImage: 'url(/src/assets/bg-pattern.webp)', backgroundSize: '400px' }}></div>
            </div>

            <div className="container mx-auto px-4 text-center relative z-10">
                <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className="flex flex-col items-center"
                >
                    <div className="relative mb-8">
                        <div className="absolute inset-0 bg-gradient-to-t from-purple-200 to-transparent rounded-full blur-xl opacity-50"></div>
                        <img src="/src/assets/medical-girl.png" alt="Medical Student" className="relative w-40 md:w-56 drop-shadow-2xl hover:scale-105 transition duration-500" />

                        {/* Floating Badges */}
                        <motion.div
                            initial={{ x: -50, opacity: 0 }}
                            animate={{ x: 0, opacity: 1 }}
                            transition={{ delay: 0.5 }}
                            className="absolute -left-12 bottom-10 bg-white p-3 rounded-xl shadow-lg flex items-center gap-2 text-xs font-bold text-gray-700"
                        >
                            <div className="bg-green-100 p-1.5 rounded-full text-green-600"><FaCheckCircle /></div>
                            <span>Verified Data</span>
                        </motion.div>
                        <motion.div
                            initial={{ x: 50, opacity: 0 }}
                            animate={{ x: 0, opacity: 1 }}
                            transition={{ delay: 0.7 }}
                            className="absolute -right-10 top-10 bg-white p-3 rounded-xl shadow-lg flex items-center gap-2 text-xs font-bold text-gray-700"
                        >
                            <div className="bg-yellow-100 p-1.5 rounded-full text-yellow-600"><FaStar /></div>
                            <span>Top Rated</span>
                        </motion.div>
                    </div>

                    <h1 className="text-5xl md:text-7xl font-extrabold mb-6 text-gray-900 leading-tight tracking-tight">
                        Get trusted guidance with <br />
                        <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#E15583] via-[#8361D0] to-[#E15583] animate-gradient-x">Sartha</span> <br />
                        for every step.
                    </h1>
                </motion.div>

                <p className="text-xl md:text-2xl text-gray-500 mb-12 max-w-3xl mx-auto font-medium leading-relaxed">
                    The Ultimate College Guidance and Counselling Platform for <span className="text-gray-900 font-bold">NEET</span> & <span className="text-gray-900 font-bold">CUET</span>
                </p>

                {/* Features - Always Visible Now */}
                <div className="flex flex-wrap justify-center gap-4 md:gap-8 text-sm font-semibold text-gray-600">
                    {["One-O-One counselling", "College Predictor", "eBooks Library", "Student Connect"].map((feat, i) => (
                        <span key={i} className="flex items-center gap-2 bg-white px-4 py-2 rounded-full shadow-sm border border-gray-100 hover:border-purple-200 transition">
                            <FaCheckCircle className="text-green-500" /> {feat}
                        </span>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default HeroSection;
