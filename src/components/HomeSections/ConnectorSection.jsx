import React from 'react';
import { Link } from 'react-router-dom';
import { FaUserCircle, FaCommentDots } from 'react-icons/fa';

const ConnectorSection = () => {
    const connectors = [
        { name: "Priya S.", college: "AIIMS Delhi", icon: "bg-blue-100 text-blue-600" },
        { name: "Rahul K.", college: "KGMU Lucknow", icon: "bg-green-100 text-green-600" },
        { name: "Sneha M.", college: "MAMC Delhi", icon: "bg-purple-100 text-purple-600" },
    ];

    return (
        <section className="py-24 bg-gradient-to-b from-[#F3F0F7] to-white relative overflow-hidden">
            <div className="container mx-auto px-4 text-center">
                <div className="inline-block bg-purple-100 text-purple-600 px-4 py-1.5 rounded-full font-bold text-sm mb-6 uppercase tracking-wide">
                    Community
                </div>
                <h2 className="text-4xl md:text-5xl font-extrabold mb-6 text-gray-900 leading-tight">
                    NextStep Counsel <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#8361D0] to-[#E15583]">Connector</span>
                </h2>
                <p className="text-gray-600 mb-16 text-lg max-w-2xl mx-auto leading-relaxed">
                    Connect directly with current medical students from your dream colleges. Get unfiltered reviews about academics, hostels, and campus life.
                </p>

                <div className="flex flex-col md:flex-row items-center justify-center gap-16">
                    {/* Visual Side */}
                    <div className="md:w-1/2 relative">
                        <div className="absolute top-10 left-10 w-20 h-20 bg-yellow-300 rounded-full blur-2xl opacity-40 animate-pulse"></div>
                        <div className="absolute bottom-10 right-10 w-32 h-32 bg-purple-300 rounded-full blur-3xl opacity-40"></div>
                        <img src="/assets/connector-illo.png" alt="NextStep Counsel Connector" className="w-full max-w-lg mx-auto drop-shadow-2xl relative z-10" />

                        {/* Floating Cards (Simulated) */}
                        <div className="absolute top-1/2 -right-4 -translate-y-1/2 bg-white p-4 rounded-xl shadow-lg animate-bounce hidden md:block">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-full bg-green-100"></div>
                                <div className="text-left">
                                    <div className="h-2 w-20 bg-gray-200 rounded mb-1"></div>
                                    <div className="h-2 w-12 bg-gray-100 rounded"></div>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Content Side */}
                    <div className="md:w-1/2 flex flex-col items-center md:items-start gap-8">
                        <div className="grid grid-cols-1 gap-6 w-full max-w-md">
                            {/* Connector Card 1 */}
                            <div className="bg-white p-6 rounded-2xl shadow-sm hover:shadow-lg transition duration-300 border border-gray-100 flex items-center gap-4">
                                <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 text-xl"><FaUserCircle /></div>
                                <div className="text-left">
                                    <h3 className="font-bold text-gray-900">Connect with Seniors</h3>
                                    <p className="text-gray-500 text-sm">Real verified students from top colleges.</p>
                                </div>
                            </div>
                            {/* Connector Card 2 */}
                            <div className="bg-white p-6 rounded-2xl shadow-sm hover:shadow-lg transition duration-300 border border-gray-100 flex items-center gap-4">
                                <div className="w-12 h-12 bg-pink-100 rounded-full flex items-center justify-center text-pink-600 text-xl"><FaCommentDots /></div>
                                <div className="text-left">
                                    <h3 className="font-bold text-gray-900">Unfiltered Insights</h3>
                                    <p className="text-gray-500 text-sm">Ask about hostel food, ragging, and academics.</p>
                                </div>
                            </div>
                        </div>

                        <Link to="/connector" className="inline-block text-center bg-gradient-to-r from-[#8361D0] to-[#E15583] text-white px-10 py-4 rounded-full font-bold hover:shadow-xl hover:shadow-purple-200 hover:-translate-y-1 transition transform w-full md:w-auto">
                            Brows Connectors
                        </Link>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default ConnectorSection;
