import React from 'react';
import { FaLock, FaDatabase, FaUserSecret, FaShareAlt } from 'react-icons/fa';

const Privacy = () => {
    return (
        <div className="font-sans min-h-screen bg-gray-50">
            {/* Header Section */}
            <div className="relative bg-gradient-to-r from-teal-900 to-emerald-900 text-white py-24 overflow-hidden">
                <div className="absolute inset-0 bg-[url('/assets/bg-pattern.webp')] opacity-10 mix-blend-overlay"></div>
                <div className="absolute top-0 left-0 w-96 h-96 bg-teal-500 rounded-full blur-[100px] opacity-20 -translate-x-1/2 -translate-y-1/2"></div>

                <div className="container mx-auto px-4 relative z-10 text-center">
                    <div className="inline-block p-4 rounded-full bg-white/10 mb-6 backdrop-blur-sm">
                        <FaUserSecret size={32} className="text-teal-300" />
                    </div>
                    <h1 className="text-4xl md:text-5xl font-extrabold mb-4 tracking-tight">Privacy Policy</h1>
                    <p className="text-lg text-teal-200 max-w-2xl mx-auto">
                        Your privacy is critically important to us. We are committed to protecting your personal information and your right to privacy.
                    </p>
                </div>
            </div>

            {/* Content Section */}
            <div className="container mx-auto px-4 py-16 -mt-10 relative z-20">
                <div className="bg-white rounded-3xl shadow-xl border border-gray-100 overflow-hidden max-w-4xl mx-auto">
                    <div className="p-8 md:p-12 space-y-12">

                        {/* Section 1 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-teal-50 rounded-xl flex items-center justify-center text-teal-600 group-hover:bg-teal-600 group-hover:text-white transition-colors duration-300">
                                <FaDatabase size={20} />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-teal-600 transition-colors">Information We Collect</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        We collect information you provide directly to us, such as when you create an account, purchase a plan, subscribe to our newsletter, or communicate with us.
                                    </p>
                                    <ul className="list-disc pl-5 space-y-2">
                                        <li><strong>Personal Data:</strong> Name, email address, phone number, and academic details (NEET score, etc.).</li>
                                        <li><strong>Payment Data:</strong> Transaction details when making purchases (we do not store your credit card information).</li>
                                    </ul>
                                </div>
                            </div>
                        </div>

                        {/* Section 2 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-emerald-50 rounded-xl flex items-center justify-center text-emerald-600 group-hover:bg-emerald-600 group-hover:text-white transition-colors duration-300">
                                <span className="font-bold text-xl">2</span>
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-emerald-600 transition-colors">How We Use Your Information</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        We use the information we collect to:
                                    </p>
                                    <ul className="list-disc pl-5 space-y-2">
                                        <li>Provide, operate, and maintain our website.</li>
                                        <li>Process your transactions and manage your orders.</li>
                                        <li>Send you emails relating to exam updates, counselling notifications, and new products.</li>
                                        <li>Personalize your experience (e.g., college predictions based on your rank).</li>
                                    </ul>
                                </div>
                            </div>
                        </div>

                        {/* Section 3 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-cyan-50 rounded-xl flex items-center justify-center text-cyan-600 group-hover:bg-cyan-600 group-hover:text-white transition-colors duration-300">
                                <FaLock size={20} />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-cyan-600 transition-colors">Data Security</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        We implement appropriate technical and organizational security measures designed to protect the security of any personal information we process. However, please also remember that we cannot guarantee that the internet itself is 100% secure.
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Section 4 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-sky-50 rounded-xl flex items-center justify-center text-sky-600 group-hover:bg-sky-600 group-hover:text-white transition-colors duration-300">
                                <FaShareAlt size={20} />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-sky-600 transition-colors">Sharing of Information</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        We <strong>do not sell</strong> your personal data. We may share information with trusted third-party service providers who assist us in operating our website, conducting our business, or serving our users, so long as those parties agree to keep this information confidential.
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

export default Privacy;
