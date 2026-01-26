import React from 'react';
import { FaArrowRight, FaChartLine, FaMapMarkedAlt, FaGlobeAsia } from 'react-icons/fa';
import { Link } from 'react-router-dom';

const PredictorSection = () => {
    return (
        <section className="py-24 bg-gray-50 relative overflow-hidden">
            {/* Decoration */}
            <div className="absolute left-0 bottom-0 w-64 h-64 bg-purple-200 rounded-tr-full blur-[80px] opacity-40"></div>

            <div className="container mx-auto px-4 flex flex-col md:flex-row-reverse items-center gap-16 relative z-10">
                <div className="md:w-1/2">
                    <div className="inline-block bg-purple-100 text-purple-600 px-4 py-1.5 rounded-full font-bold text-sm mb-6 uppercase tracking-wide">
                        AI Powered
                    </div>
                    <h2 className="text-4xl md:text-5xl font-extrabold mb-6 text-gray-900 leading-tight">
                        NEET College <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#8361D0] to-[#E15583]">Predictor</span>
                    </h2>
                    <p className="text-gray-600 mb-10 text-lg leading-relaxed">
                        Our advanced algorithm analyzes over 100+ parameters to predict your chances of getting admission into your dream college with high accuracy.
                    </p>

                    <div className="grid grid-cols-2 gap-6 mb-10">
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 hover:shadow-md hover:border-purple-200 transition group">
                            <div className="w-10 h-10 bg-purple-50 rounded-lg flex items-center justify-center text-purple-600 mb-4 group-hover:scale-110 transition">
                                <FaMapMarkedAlt />
                            </div>
                            <h4 className="font-bold text-gray-900 mb-2">State Predictor</h4>
                            <p className="text-xs text-gray-500">85% State Quota predictions with category accuracy.</p>
                        </div>
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 hover:shadow-md hover:border-purple-200 transition group">
                            <div className="w-10 h-10 bg-purple-50 rounded-lg flex items-center justify-center text-purple-600 mb-4 group-hover:scale-110 transition">
                                <FaGlobeAsia />
                            </div>
                            <h4 className="font-bold text-gray-900 mb-2">All India Predictor</h4>
                            <p className="text-xs text-gray-500">15% AIQ predictions for all central universities.</p>
                        </div>
                    </div>

                    <Link to="/predictor" className="inline-flex bg-white text-[#8361D0] border-2 border-[#8361D0] px-8 py-4 rounded-full font-bold items-center gap-2 hover:bg-[#8361D0] hover:text-white transition transform hover:-translate-y-1">
                        Try Predictor Now <FaArrowRight />
                    </Link>
                </div>
                <div className="md:w-1/2 flex justify-center relative">
                    <div className="absolute inset-0 bg-gradient-to-tl from-purple-200 to-indigo-200 rounded-full blur-3xl opacity-30"></div>
                    {/* Illustration */}
                    <img src="/src/assets/predictor-tool.png" alt="College Predictor" className="w-full max-w-lg relative z-10 drop-shadow-2xl hover:scale-[1.02] transition duration-700" />
                </div>
            </div>
        </section>
    );
};

export default PredictorSection;
