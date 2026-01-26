import React from 'react';
import { FaUndo, FaRegClock, FaHeadset, FaBan } from 'react-icons/fa';

const Refund = () => {
    return (
        <div className="font-sans min-h-screen bg-gray-50">
            {/* Header Section */}
            <div className="relative bg-gradient-to-r from-emerald-900 to-green-900 text-white py-24 overflow-hidden">
                <div className="absolute inset-0 bg-[url('/assets/bg-pattern.webp')] opacity-10 mix-blend-overlay"></div>
                <div className="absolute bottom-0 right-0 w-96 h-96 bg-green-500 rounded-full blur-[100px] opacity-20 translate-y-1/2 translate-x-1/2"></div>

                <div className="container mx-auto px-4 relative z-10 text-center">
                    <div className="inline-block p-4 rounded-full bg-white/10 mb-6 backdrop-blur-sm">
                        <FaUndo size={32} className="text-green-300" />
                    </div>
                    <h1 className="text-4xl md:text-5xl font-extrabold mb-4 tracking-tight">Refund Policy</h1>
                    <p className="text-lg text-green-200 max-w-2xl mx-auto">
                        Transparent and fair. We believe in building trust with our community. Here's how our refund process works.
                    </p>
                </div>
            </div>

            {/* Content Section */}
            <div className="container mx-auto px-4 py-16 -mt-10 relative z-20">
                <div className="bg-white rounded-3xl shadow-xl border border-gray-100 overflow-hidden max-w-4xl mx-auto">
                    <div className="p-8 md:p-12 space-y-12">

                        {/* Section 1 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-red-50 rounded-xl flex items-center justify-center text-red-600 group-hover:bg-red-600 group-hover:text-white transition-colors duration-300">
                                <FaBan size={20} />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-red-600 transition-colors">Digital Products</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        Due to the nature of digital products (eBooks, PDF guides, Premium Lists) which can be instantly downloaded, <strong>all sales are final</strong>.
                                    </p>
                                    <p>
                                        We do not offer refunds once the digital content has been accessed or downloaded, as there is no way to "return" the product.
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Section 2 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-green-50 rounded-xl flex items-center justify-center text-green-600 group-hover:bg-green-600 group-hover:text-white transition-colors duration-300">
                                <FaRegClock size={20} />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-green-600 transition-colors">Counselling Services</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        Refunds for personalized counselling packages are considered only if:
                                    </p>
                                    <ul className="list-disc pl-5 space-y-2">
                                        <li>The request is made within <strong>24 hours</strong> of purchase.</li>
                                        <li><strong>AND</strong> no service (counselling session, preference list generation, or WhatsApp group access) has been utilized.</li>
                                    </ul>
                                    <p>
                                        If we are unable to assign a counsellor to you within 72 hours of purchase, you are eligible for a 100% refund.
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Section 3 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-blue-50 rounded-xl flex items-center justify-center text-blue-600 group-hover:bg-blue-600 group-hover:text-white transition-colors duration-300">
                                <span className="font-bold text-xl">3</span>
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-blue-600 transition-colors">Processing Refunds</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        Approved refunds will be processed within <strong>5-7 business days</strong> and credited back to the original payment method. You will receive an email confirmation once the refund is initiated.
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Section 4 */}
                        <div className="flex gap-6 items-start group">
                            <div className="flex-shrink-0 w-12 h-12 bg-purple-50 rounded-xl flex items-center justify-center text-purple-600 group-hover:bg-purple-600 group-hover:text-white transition-colors duration-300">
                                <FaHeadset size={20} />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 mb-4 group-hover:text-purple-600 transition-colors">Contact Us</h2>
                                <div className="text-gray-600 leading-relaxed space-y-4">
                                    <p>
                                        If you have any questions about our Refund Policy, please contact our support team before making a purchase.
                                    </p>
                                    <p>
                                        <a href="mailto:support@sartha.in" className="text-purple-600 font-bold hover:underline">support@sartha.in</a>
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

export default Refund;
