import React, { useState } from 'react';
import { FaDownload, FaListAlt, FaCheckCircle, FaSpinner, FaFilePdf } from 'react-icons/fa';

const PreferenceList = () => {
    const [formData, setFormData] = useState({
        rank: '',
        category: 'General',
        state: ''
    });
    const [isGenerating, setIsGenerating] = useState(false);
    const [generationSuccess, setGenerationSuccess] = useState(false);

    const handleInputChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleGenerate = () => {
        if (!formData.rank) {
            alert("Please enter your rank.");
            return;
        }

        setIsGenerating(true);
        setGenerationSuccess(false);

        // Simulate API call
        setTimeout(() => {
            setIsGenerating(false);
            setGenerationSuccess(true);
            // In a real app, this would trigger an email or download
        }, 2000);
    };

    const handleDownloadSample = () => {
        // Using the actual sample link from the reference site if available, or a reliable placeholder
        const sampleUrl = "#"; // Placeholder
        window.open(sampleUrl, '_blank');
    };

    return (
        <div className="pt-24 pb-16 min-h-screen bg-gray-50 font-sans">
            {/* Hero Section */}
            <div className="relative bg-gradient-to-r from-purple-900 to-indigo-900 text-white py-20 mb-12 -mt-24">
                <div className="absolute inset-0 bg-[url('/assets/bg-pattern.webp')] opacity-10 mix-blend-overlay"></div>

                <div className="container mx-auto px-4 relative z-10 text-center pt-24">
                    <h1 className="text-4xl md:text-5xl font-extrabold mb-4 tracking-tight">NEET Preference List</h1>
                    <p className="text-lg text-purple-200 max-w-3xl mx-auto">
                        Create your personalized, scientifically optimized preference list in seconds. maximize your chances of securing a seat.
                    </p>
                </div>
            </div>

            <div className="container mx-auto px-4">
                <div className="max-w-5xl mx-auto">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        {/* Generator Card */}
                        <div className="bg-white p-8 rounded-2xl shadow-xl border border-gray-100">
                            <div className="flex items-center gap-4 mb-6">
                                <div className="w-12 h-12 bg-purple-50 rounded-xl flex items-center justify-center text-purple-600 text-2xl">
                                    <FaListAlt />
                                </div>
                                <div>
                                    <h3 className="text-2xl font-bold text-gray-900">Generate Your List</h3>
                                    <p className="text-gray-500 text-sm">Enter details to get a customized PDF</p>
                                </div>
                            </div>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-gray-700 font-bold mb-2">NEET Rank</label>
                                    <input
                                        type="number"
                                        name="rank"
                                        placeholder="Enter your All India Rank"
                                        className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                                        value={formData.rank}
                                        onChange={handleInputChange}
                                    />
                                </div>
                                <div>
                                    <label className="block text-gray-700 font-bold mb-2">Category</label>
                                    <select
                                        name="category"
                                        className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                                        value={formData.category}
                                        onChange={handleInputChange}
                                    >
                                        <option value="General">General / Unreserved</option>
                                        <option value="OBC">OBC</option>
                                        <option value="SC">SC</option>
                                        <option value="ST">ST</option>
                                        <option value="EWS">EWS</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-gray-700 font-bold mb-2">Preferred State</label>
                                    <select
                                        name="state"
                                        className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                                        value={formData.state}
                                        onChange={handleInputChange}
                                    >
                                        <option value="">All India</option>
                                        <option value="Delhi">Delhi</option>
                                        <option value="Maharashtra">Maharashtra</option>
                                        <option value="Karnataka">Karnataka</option>
                                        <option value="Tamil Nadu">Tamil Nadu</option>
                                        <option value="Uttar Pradesh">Uttar Pradesh</option>
                                    </select>
                                </div>

                                {generationSuccess && (
                                    <div className="bg-green-50 text-green-700 p-4 rounded-lg flex items-start gap-3 border border-green-200 animate-fade-in">
                                        <FaCheckCircle className="mt-1 flex-shrink-0" />
                                        <div>
                                            <p className="font-bold">Success!</p>
                                            <p className="text-sm">Your preference list has been generated. Since this is a demo, please check the sample or contact support for the full file.</p>
                                        </div>
                                    </div>
                                )}

                                <button
                                    onClick={handleGenerate}
                                    disabled={isGenerating}
                                    className={`w-full py-4 rounded-xl font-bold text-white transition-all flex items-center justify-center gap-2 ${isGenerating ? 'bg-gray-400 cursor-not-allowed' : 'bg-gradient-to-r from-purple-600 to-indigo-600 hover:shadow-lg hover:scale-[1.02]'}`}
                                >
                                    {isGenerating ? (
                                        <><FaSpinner className="animate-spin" /> Generating...</>
                                    ) : (
                                        "Generate Preference List"
                                    )}
                                </button>
                            </div>
                        </div>

                        {/* Download Sample Card */}
                        <div className="flex flex-col gap-6">
                            <div className="bg-white p-8 rounded-2xl shadow-xl border border-gray-100 flex-grow">
                                <div className="flex items-center gap-4 mb-6">
                                    <div className="w-12 h-12 bg-blue-50 rounded-xl flex items-center justify-center text-blue-600 text-2xl">
                                        <FaDownload />
                                    </div>
                                    <div>
                                        <h3 className="text-2xl font-bold text-gray-900">Sample List</h3>
                                        <p className="text-gray-500 text-sm">See what a perfect list looks like</p>
                                    </div>
                                </div>
                                <p className="text-gray-600 mb-6 leading-relaxed">
                                    Not sure where to start? Download our sample preference list to understand how to prioritize top colleges, arrange choices based on last year's cutoffs, and avoid common mistakes.
                                </p>

                                <div className="bg-gray-50 p-4 rounded-lg mb-6 border border-gray-200">
                                    <div className="flex items-center gap-3 mb-2">
                                        <FaFilePdf className="text-red-500 text-xl" />
                                        <span className="font-bold text-gray-800">Sample_Preference_List.pdf</span>
                                    </div>
                                    <p className="text-xs text-gray-500 ml-8">Size: 1.2 MB • Format: PDF</p>
                                </div>

                                <button
                                    onClick={handleDownloadSample}
                                    className="w-full bg-white text-blue-600 border-2 border-blue-600 py-3 rounded-xl font-bold hover:bg-blue-50 transition flex items-center justify-center gap-2"
                                >
                                    <FaDownload /> Download Sample PDF
                                </button>
                            </div>

                            {/* Help Box */}
                            <div className="bg-gradient-to-r from-pink-500 to-rose-500 p-8 rounded-2xl shadow-lg text-white">
                                <h3 className="text-xl font-bold mb-2">Need Expert Help?</h3>
                                <p className="mb-4 opacity-90 text-sm">Our counsellors can create a hand-picked preference list just for you.</p>
                                <button className="bg-white text-pink-600 px-6 py-2 rounded-full font-bold text-sm hover:shadow-lg transition">
                                    Book Session
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* How it Works Section */}
                    <div className="mt-16 text-center">
                        <h2 className="text-3xl font-bold text-gray-900 mb-12">How It Works</h2>
                        <div className="grid md:grid-cols-3 gap-8">
                            <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                                <div className="w-10 h-10 bg-purple-100 text-purple-600 rounded-full flex items-center justify-center mx-auto mb-4 font-bold text-lg">1</div>
                                <h4 className="font-bold mb-2">Enter Details</h4>
                                <p className="text-gray-500 text-sm">Input your rank, category, and preferred branch focus.</p>
                            </div>
                            <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                                <div className="w-10 h-10 bg-indigo-100 text-indigo-600 rounded-full flex items-center justify-center mx-auto mb-4 font-bold text-lg">2</div>
                                <h4 className="font-bold mb-2">AI Analysis</h4>
                                <p className="text-gray-500 text-sm">Our algorithm checks 5 years of cutoff data and seat matrices.</p>
                            </div>
                            <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                                <div className="w-10 h-10 bg-green-100 text-green-600 rounded-full flex items-center justify-center mx-auto mb-4 font-bold text-lg">3</div>
                                <h4 className="font-bold mb-2">Get List</h4>
                                <p className="text-gray-500 text-sm">Download your optimized preference list instantly.</p>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    );
};

export default PreferenceList;
