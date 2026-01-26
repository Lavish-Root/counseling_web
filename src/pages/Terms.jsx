import React from 'react';
import { FaFileContract, FaUserShield, FaGavel, FaExclamationCircle } from 'react-icons/fa';

const Terms = () => {
    return (
        <div className="font-sans min-h-screen bg-gray-50">
            {/* Header Section */}
            <div className="relative bg-gradient-to-r from-blue-900 to-indigo-900 text-white py-24 overflow-hidden">
                <div className="absolute inset-0 bg-[url('/assets/bg-pattern.webp')] opacity-10 mix-blend-overlay"></div>
                <div className="absolute top-0 right-0 w-96 h-96 bg-blue-500 rounded-full blur-[100px] opacity-20 translate-x-1/2 -translate-y-1/2"></div>

                <div className="container mx-auto px-4 relative z-10 text-center">
                    <div className="inline-block p-4 rounded-full bg-white/10 mb-6 backdrop-blur-sm">
                        <FaFileContract size={32} className="text-blue-300" />
                    </div>
                    <h1 className="text-4xl md:text-5xl font-extrabold mb-4 tracking-tight">Terms & Conditions</h1>
                    <p className="text-lg text-blue-200 max-w-2xl mx-auto">
                        Please read these terms carefully before using our services. By using Sartha, you agree to be bound by these conditions.
                    </p>
                </div>
            </div>

            {/* Content Section */}
            <div className="container mx-auto px-4 py-16 -mt-10 relative z-20">
                <div className="bg-white rounded-3xl shadow-xl border border-gray-100 overflow-hidden max-w-4xl mx-auto">
                    <div className="p-8 md:p-12 space-y-12">

                        {/* Section 1 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-blue-50 rounded-xl flex items-center justify-center text-blue-600 group-hover:bg-blue-600 group-hover:text-white transition-colors duration-300">
                                <span className="font-bold text-xl">1</span>
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-blue-600 transition-colors">Acceptance of Terms</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        By accessing and using <strong>Sartha.in</strong> ("we", "us", or "our"), you accept and agree to be bound by the terms and provisions of this agreement. In addition, when using these particular services, you shall be subject to any posted guidelines or rules applicable to such services.
                                    </p>
                                    <p>
                                        ANY PARTICIPATION IN THIS SERVICE WILL CONSTITUTE ACCEPTANCE OF THIS AGREEMENT. IF YOU DO NOT AGREE TO ABIDE BY THE ABOVE, PLEASE DO NOT USE THIS SERVICE.
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Section 2 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-indigo-50 rounded-xl flex items-center justify-center text-indigo-600 group-hover:bg-indigo-600 group-hover:text-white transition-colors duration-300">
                                <span className="font-bold text-xl">2</span>
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-indigo-600 transition-colors">Use of Services</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        Our services, including counselling guidance, college predictors, and eBooks, are for <strong>educational and informational purposes only</strong>. While the information contained within the site is periodically updated, no guarantee is given that the information provided in this website is correct, complete, and up-to-date.
                                    </p>
                                    <p>
                                        We do not guarantee admission to any specific college. Admission is subject to your merit, rank, and government regulations.
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Section 3 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-purple-50 rounded-xl flex items-center justify-center text-purple-600 group-hover:bg-purple-600 group-hover:text-white transition-colors duration-300">
                                <FaUserShield size={20} />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-purple-600 transition-colors">User Accounts</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        To access certain features, you may need to create an account. You are responsible for maintaining the confidentiality of your account credentials (username and password).
                                    </p>
                                    <p>
                                        You are responsible for all activities that occur under your account. You agree to notify us immediately of any unauthorized use of your account.
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Section 4 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-pink-50 rounded-xl flex items-center justify-center text-pink-600 group-hover:bg-pink-600 group-hover:text-white transition-colors duration-300">
                                <FaGavel size={20} />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-pink-600 transition-colors">Intellectual Property</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        All content on this website, including text, graphics, logos, images, and software, is the property of Sartha Education and is protected by copyright laws.
                                    </p>
                                    <p>
                                        You may not reproduce, duplicate, copy, sell, resell or exploit any portion of the service, use of the service, or access to the service without express written permission by us.
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Section 5 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-red-50 rounded-xl flex items-center justify-center text-red-600 group-hover:bg-red-600 group-hover:text-white transition-colors duration-300">
                                <FaExclamationCircle size={20} />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-red-600 transition-colors">Limitation of Liability</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        Sartha Education shall not be liable for any indirect, incidental, special, consequential or punitive damages, or any loss of profits or revenues, whether incurred directly or indirectly.
                                    </p>
                                </div>
                            </div>
                        </div>

                    </div>

                    <div className="bg-gray-50 px-8 py-6 border-t border-gray-100 text-center">
                        <p className="text-gray-500 font-medium">Last updated: January 2025</p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Terms;
