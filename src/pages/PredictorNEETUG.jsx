import React, { useState } from 'react';
import { FaRobot, FaSearchLocation, FaFilePdf, FaCheckCircle, FaSpinner } from 'react-icons/fa';

const PredictorNEETUG = () => {
    const [formData, setFormData] = useState({
        rank: '',
        category: 'General',
        state: '',
        course: 'MBBS'
    });
    const [isPredicting, setIsPredicting] = useState(false);
    const [predictionSuccess, setPredictionSuccess] = useState(false);

    const handleInputChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handlePredict = () => {
        if (!formData.rank) {
            alert("Please enter your NEET Rank.");
            return;
        }

        setIsPredicting(true);
        setPredictionSuccess(false);

        // Simulate API/Prediction Process
        setTimeout(() => {
            setIsPredicting(false);
            setPredictionSuccess(true);
        }, 2000);
    };

    return (
        <div className="font-sans min-h-screen bg-gray-50">
            {/* Hero Section */}
            <div className="relative bg-gradient-to-r from-blue-900 to-cyan-900 text-white py-20 lg:py-28">
                <div className="absolute inset-0 bg-[url('/assets/bg-pattern.webp')] opacity-10 mix-blend-overlay"></div>
                <div className="absolute bottom-0 left-0 w-96 h-96 bg-cyan-500 rounded-full blur-[100px] opacity-20 -translate-x-1/2 translate-y-1/2"></div>

                <div className="container mx-auto px-4 relative z-10 text-center">
                    <h1 className="text-4xl md:text-5xl font-extrabold mb-6 tracking-tight">NEET UG 2025 College Predictor</h1>
                    <p className="text-lg text-cyan-100 max-w-3xl mx-auto mb-8">
                        Get your personalized PDF report with college predictions for MBBS, BDS, AYUSH, and BVSC courses - including fees, last year's cut-offs, and chances.
                    </p>
                </div>
            </div>

            {/* Predictor Section */}
            <div className="container mx-auto px-4 py-16 -mt-20 relative z-20">
                <div className="bg-white rounded-3xl shadow-2xl border border-gray-100 overflow-hidden max-w-5xl mx-auto flex flex-col md:flex-row">

                    {/* Left: Form */}
                    <div className="md:w-3/5 p-8 md:p-12">
                        <div className="flex items-center gap-4 mb-8">
                            <div className="w-12 h-12 bg-blue-50 rounded-xl flex items-center justify-center text-blue-600 text-2xl">
                                <FaSearchLocation />
                            </div>
                            <div>
                                <h3 className="text-2xl font-bold text-gray-900">Find Your College</h3>
                                <p className="text-gray-500 text-sm">Enter details to get predictions</p>
                            </div>
                        </div>

                        <div className="space-y-6">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div>
                                    <label className="block text-gray-700 font-bold mb-2">NEET Rank</label>
                                    <input
                                        type="number"
                                        name="rank"
                                        placeholder="e.g. 15000"
                                        className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500 bg-gray-50"
                                        value={formData.rank}
                                        onChange={handleInputChange}
                                    />
                                </div>
                                <div>
                                    <label className="block text-gray-700 font-bold mb-2">Category</label>
                                    <select
                                        name="category"
                                        className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500 bg-gray-50"
                                        value={formData.category}
                                        onChange={handleInputChange}
                                    >
                                        <option value="General">General / Open</option>
                                        <option value="OBC">OBC</option>
                                        <option value="EWS">EWS</option>
                                        <option value="SC">SC</option>
                                        <option value="ST">ST</option>
                                    </select>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div>
                                    <label className="block text-gray-700 font-bold mb-2">Home State</label>
                                    <select
                                        name="state"
                                        className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500 bg-gray-50"
                                        value={formData.state}
                                        onChange={handleInputChange}
                                    >
                                        <option value="">Select State</option>
                                        <option value="Delhi">Delhi</option>
                                        <option value="Uttar Pradesh">Uttar Pradesh</option>
                                        <option value="Maharashtra">Maharashtra</option>
                                        <option value="Karnataka">Karnataka</option>
                                        <option value="Rajasthan">Rajasthan</option>
                                        <option value="Other">Other</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-gray-700 font-bold mb-2">Course Interest</label>
                                    <select
                                        name="course"
                                        className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500 bg-gray-50"
                                        value={formData.course}
                                        onChange={handleInputChange}
                                    >
                                        <option value="MBBS">MBBS</option>
                                        <option value="BDS">BDS</option>
                                        <option value="BAMS">BAMS</option>
                                        <option value="BVSc">BVSc & AH</option>
                                    </select>
                                </div>
                            </div>

                            {predictionSuccess && (
                                <div className="bg-green-50 text-green-700 p-4 rounded-xl flex items-start gap-3 border border-green-100 animate-fade-in">
                                    <FaCheckCircle className="mt-1 flex-shrink-0 text-xl" />
                                    <div>
                                        <p className="font-bold text-lg">Prediction Ready!</p>
                                        <p className="text-sm">Based on your rank <strong>{formData.rank}</strong>, we found <strong>24+ Colleges</strong> you are eligible for.</p>
                                        <button className="mt-3 text-white bg-green-600 px-4 py-2 rounded-lg text-sm font-bold hover:bg-green-700 transition cursor-pointer">
                                            Download Report
                                        </button>
                                    </div>
                                </div>
                            )}

                            <button
                                onClick={handlePredict}
                                disabled={isPredicting}
                                className={`w-full py-4 rounded-xl font-bold text-white text-lg shadow-lg hover:shadow-xl transition-all flex items-center justify-center gap-2 ${isPredicting ? 'bg-gray-400 cursor-not-allowed' : 'bg-gradient-to-r from-blue-600 to-cyan-600 hover:scale-[1.02] cursor-pointer'}`}
                            >
                                {isPredicting ? (
                                    <><FaSpinner className="animate-spin" /> Analyzing 1500+ Colleges...</>
                                ) : (
                                    "Predict My Colleges"
                                )}
                            </button>
                        </div>
                    </div>

                    {/* Right: Info/Features */}
                    <div className="md:w-2/5 bg-gray-50 p-8 md:p-12 border-l border-gray-100 flex flex-col justify-center">
                        <div className="mb-8">
                            <h3 className="text-xl font-bold text-gray-800 mb-6">Why use our Predictor?</h3>
                            <ul className="space-y-4">
                                <li className="flex items-start gap-3">
                                    <div className="bg-white p-2 rounded-lg shadow-sm text-blue-500"><FaRobot /></div>
                                    <span className="text-gray-600"><strong>AI-Powered Accuracy</strong>: Uses last 5 years of cutoff data trend analysis.</span>
                                </li>
                                <li className="flex items-start gap-3">
                                    <div className="bg-white p-2 rounded-lg shadow-sm text-green-500"><FaSearchLocation /></div>
                                    <span className="text-gray-600"><strong>AIQ + State Quota</strong>: Covers 15% All India Quota and 85% State Quota seats.</span>
                                </li>
                                <li className="flex items-start gap-3">
                                    <div className="bg-white p-2 rounded-lg shadow-sm text-red-500"><FaFilePdf /></div>
                                    <span className="text-gray-600"><strong>Instant PDF Report</strong>: Download a detailed list with fee structures and bond details.</span>
                                </li>
                            </ul>
                        </div>

                        <div className="bg-blue-100 p-6 rounded-xl text-blue-800 text-sm">
                            <span className="font-bold block mb-1">Note:</span>
                            Prediction is based on previous year trends. Actual cutoffs may vary depending on this year's difficulty level and seat matrix.
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default PredictorNEETUG;
