import React from 'react';
import { FaCheck, FaArrowRight } from 'react-icons/fa';
import { Link } from 'react-router-dom';

const OneOnOneSection = () => {
    const features = [
        "Registration Form Filling Support",
        "Document Verification Support",
        "All India & State Counselling covered",
        "Scholarship Guidance",
        "Deep Analysis of last 5 year cutoffs",
        "Preference list making"
    ];

    return (
        <section className="py-24 bg-white relative overflow-hidden">
            <div className="absolute top-0 right-0 w-96 h-96 bg-pink-100 rounded-full blur-[120px] opacity-40"></div>

            <div className="container mx-auto px-4 flex flex-col md:flex-row items-center gap-16 relative z-10">
                <div className="md:w-1/2">
                    <div className="inline-block bg-pink-100 text-pink-600 px-4 py-1.5 rounded-full font-bold text-sm mb-6 uppercase tracking-wide">
                        Personal Guidance
                    </div>
                    <h2 className="text-4xl md:text-5xl font-extrabold mb-6 text-gray-900 leading-tight">
                        One-On-One Personalised <br /><span className="text-transparent bg-clip-text bg-gradient-to-r from-[#E15583] to-[#8361D0]">Counselling</span>
                    </h2>
                    <p className="text-gray-600 mb-10 text-lg leading-relaxed">
                        Get a dedicated expert counsellor who will guide you through the entire admission process, from rank analysis to college reporting, ensuring you make no mistakes.
                    </p>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-10">
                        {features.map((feature, index) => (
                            <div key={index} className="flex items-center gap-3 text-gray-700 bg-gray-50 p-3 rounded-lg border border-gray-100/50 hover:bg-white hover:shadow-md transition duration-300">
                                <div className="bg-green-100 p-1.5 rounded-full text-green-600 flex-shrink-0">
                                    <FaCheck size={10} />
                                </div>
                                <span className="text-sm font-medium">{feature}</span>
                            </div>
                        ))}
                    </div>

                    <Link to="/counselling" className="inline-flex bg-gradient-to-r from-[#E15583] to-[#8361D0] text-white px-8 py-4 rounded-full font-bold items-center gap-2 hover:shadow-lg hover:shadow-pink-200 hover:-translate-y-1 transition transform">
                        View Premium Plans <FaArrowRight />
                    </Link>
                </div>
                <div className="md:w-1/2 flex justify-center relative">
                    <div className="absolute inset-0 bg-gradient-to-tr from-pink-200 to-purple-200 rounded-full blur-3xl opacity-30 transform rotate-12"></div>
                    <img
                        src="/src/assets/counselling-support.png"
                        alt="Personalised Counselling"
                        className="w-full max-w-lg relative z-10 drop-shadow-2xl hover:scale-[1.02] transition duration-700"
                    />
                </div>
            </div>
        </section>
    );
};

export default OneOnOneSection;
