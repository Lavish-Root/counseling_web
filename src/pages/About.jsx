import React from 'react';
import { FaExclamationTriangle, FaInfoCircle, FaLightbulb, FaHeart, FaUserTie, FaUsers, FaRupeeSign, FaTools, FaCheckCircle, FaLinkedin, FaTwitter } from 'react-icons/fa';

const About = () => {
    return (
        <div className="font-sans text-gray-800">
            {/* Hero Section */}
            <section className="relative bg-gradient-to-br from-[#1a1025] to-[#2d1b42] text-white py-24 lg:py-32 overflow-hidden">
                <div className="absolute inset-0 bg-[url('/src/assets/bg-pattern.webp')] opacity-5 mix-blend-overlay"></div>
                <div className="container mx-auto px-4 relative z-10 text-center max-w-4xl">
                    <h1 className="text-4xl md:text-6xl font-extrabold mb-8 leading-tight">
                        Your Dreams, <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#E15583] to-[#8361D0]">Our Mission</span>
                    </h1>
                    <p className="text-xl text-gray-300 leading-relaxed mb-8">
                        Making your admission journey smooth, informed, and stress-free. Sartha was created with a single purpose: to ensure you have the clarity and confidence to achieve your dreams.
                    </p>
                </div>
            </section>

            {/* The Problems We're Solving */}
            <section className="py-20 bg-gray-50">
                <div className="container mx-auto px-4">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl font-bold text-gray-900">The Problems We're Solving</h2>
                        <div className="w-20 h-1 bg-gradient-to-r from-[#E15583] to-[#8361D0] mx-auto mt-4 rounded-full"></div>
                    </div>

                    <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8 max-w-7xl mx-auto">
                        <div className="bg-white p-8 rounded-2xl shadow-sm hover:shadow-xl transition duration-300 border border-red-50 group">
                            <div className="w-14 h-14 bg-red-50 rounded-xl flex items-center justify-center text-red-500 text-2xl mb-6 group-hover:bg-red-500 group-hover:text-white transition">
                                <FaInfoCircle />
                            </div>
                            <h3 className="text-xl font-bold mb-3">Incomplete Information</h3>
                            <p className="text-gray-600 text-sm leading-relaxed">
                                Important details like fees, bonds, hostel conditions, and cutoffs are often unclear or outdated.
                            </p>
                        </div>
                        <div className="bg-white p-8 rounded-2xl shadow-sm hover:shadow-xl transition duration-300 border border-orange-50 group">
                            <div className="w-14 h-14 bg-orange-50 rounded-xl flex items-center justify-center text-orange-500 text-2xl mb-6 group-hover:bg-orange-500 group-hover:text-white transition">
                                <FaExclamationTriangle />
                            </div>
                            <h3 className="text-xl font-bold mb-3">Misleading Guidance</h3>
                            <p className="text-gray-600 text-sm leading-relaxed">
                                Families often face overpriced counselors who charge exorbitant fees but fail to deliver results.
                            </p>
                        </div>
                        <div className="bg-white p-8 rounded-2xl shadow-sm hover:shadow-xl transition duration-300 border border-yellow-50 group">
                            <div className="w-14 h-14 bg-yellow-50 rounded-xl flex items-center justify-center text-yellow-500 text-2xl mb-6 group-hover:bg-yellow-500 group-hover:text-white transition">
                                <FaLightbulb />
                            </div>
                            <h3 className="text-xl font-bold mb-3">Lack of Real Insights</h3>
                            <p className="text-gray-600 text-sm leading-relaxed">
                                Official brochures don't reveal hidden charges, food quality, or the real campus environment.
                            </p>
                        </div>
                        <div className="bg-white p-8 rounded-2xl shadow-sm hover:shadow-xl transition duration-300 border border-blue-50 group">
                            <div className="w-14 h-14 bg-blue-50 rounded-xl flex items-center justify-center text-blue-500 text-2xl mb-6 group-hover:bg-blue-500 group-hover:text-white transition">
                                <FaHeart />
                            </div>
                            <h3 className="text-xl font-bold mb-3">Unnecessary Stress</h3>
                            <p className="text-gray-600 text-sm leading-relaxed">
                                Confusion leads to anxiety. We aim to replace that with confidence and clarity.
                            </p>
                        </div>
                    </div>
                </div>
            </section>

            {/* Why Choose Sartha? */}
            <section className="py-20 bg-white">
                <div className="container mx-auto px-4">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl font-bold text-gray-900">Why Choose Sartha?</h2>
                        <div className="w-20 h-1 bg-gradient-to-r from-[#E15583] to-[#8361D0] mx-auto mt-4 rounded-full"></div>
                    </div>

                    <div className="grid md:grid-cols-2 gap-12 max-w-6xl mx-auto items-center">
                        <div className="space-y-8">
                            <div className="flex gap-4">
                                <div className="flex-shrink-0 w-12 h-12 bg-purple-50 rounded-full flex items-center justify-center text-purple-600">
                                    <FaUserTie size={20} />
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold mb-2">Expert Guidance You Can Trust</h3>
                                    <p className="text-gray-600">Team of 20+ experienced counselors guiding you through preference lists, bonds, and fees.</p>
                                </div>
                            </div>
                            <div className="flex gap-4">
                                <div className="flex-shrink-0 w-12 h-12 bg-pink-50 rounded-full flex items-center justify-center text-pink-600">
                                    <FaUsers size={20} />
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold mb-2">Real Advice from Real Students</h3>
                                    <p className="text-gray-600">Directly connect with current college students via Sartha Connector for unfiltered insights.</p>
                                </div>
                            </div>
                            <div className="flex gap-4">
                                <div className="flex-shrink-0 w-12 h-12 bg-green-50 rounded-full flex items-center justify-center text-green-600">
                                    <FaRupeeSign size={20} />
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold mb-2">Affordable for Every Student</h3>
                                    <p className="text-gray-600">While others charge ₹50k+, we start at just ₹3,000–₹4,000 with customized plans.</p>
                                </div>
                            </div>
                            <div className="flex gap-4">
                                <div className="flex-shrink-0 w-12 h-12 bg-blue-50 rounded-full flex items-center justify-center text-blue-600">
                                    <FaTools size={20} />
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold mb-2">All the Tools You Need</h3>
                                    <p className="text-gray-600">AI-powered college predictor, detailed eBooks, and personalized counseling sessions.</p>
                                </div>
                            </div>
                            <div className="flex gap-4">
                                <div className="flex-shrink-0 w-12 h-12 bg-teal-50 rounded-full flex items-center justify-center text-teal-600">
                                    <FaCheckCircle size={20} />
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold mb-2">Up-to-Date, Reliable Information</h3>
                                    <p className="text-gray-600">Real-time data on fees, cutoffs, and regulations to ensure informed decisions.</p>
                                </div>
                            </div>
                        </div>
                        <div className="relative">
                            <div className="absolute inset-0 bg-gradient-to-r from-[#E15583] to-[#8361D0] rounded-2xl transform rotate-3 opacity-20"></div>
                            <img
                                src="https://images.unsplash.com/photo-1523240795612-9a054b0db644?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80"
                                alt="Students discussing"
                                className="relative rounded-2xl shadow-xl w-full h-auto object-cover"
                            />
                        </div>
                    </div>
                </div>
            </section>

            {/* Founders Section */}
            <section className="py-20 bg-gray-50">
                <div className="container mx-auto px-4">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl font-bold text-gray-900">From Founder's Desk</h2>
                        <div className="w-20 h-1 bg-gradient-to-r from-[#E15583] to-[#8361D0] mx-auto mt-4 rounded-full"></div>
                    </div>

                    <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
                        {/* Founder 1 */}
                        <div className="bg-white rounded-2xl overflow-hidden shadow-lg border border-gray-100 group">
                            <div className="h-2 bg-gradient-to-r from-blue-500 to-cyan-500"></div>
                            <div className="p-8 text-center">
                                <div className="mb-6 relative inline-block">
                                    <div className="absolute inset-0 bg-blue-500 rounded-full blur opacity-20"></div>
                                    <img
                                        src="https://placehold.co/150x150/0ea5e9/ffffff?text=JG"
                                        alt="Dr. Jayesh Ghanchi"
                                        className="w-32 h-32 rounded-full object-cover relative border-4 border-white shadow-md mx-auto"
                                    />
                                </div>
                                <h3 className="text-2xl font-bold text-gray-900">Dr. Jayesh Ghanchi</h3>
                                <p className="text-blue-600 font-medium mb-4">Founder & CEO</p>
                                <p className="text-gray-500 text-sm mb-6">MBBS | NAMO MERI (GMC), Silvassa</p>
                                <p className="text-gray-600 italic leading-relaxed">
                                    "During my own counseling journey, I saw how confusing and stressful the process can be. That experience made me realize the need for a platform like Sartha."
                                </p>
                            </div>
                        </div>

                        {/* Founder 2 */}
                        <div className="bg-white rounded-2xl overflow-hidden shadow-lg border border-gray-100 group">
                            <div className="h-2 bg-gradient-to-r from-purple-500 to-pink-500"></div>
                            <div className="p-8 text-center">
                                <div className="mb-6 relative inline-block">
                                    <div className="absolute inset-0 bg-purple-500 rounded-full blur opacity-20"></div>
                                    <img
                                        src="https://placehold.co/150x150/8361D0/ffffff?text=AS"
                                        alt="Akash Satyam"
                                        className="w-32 h-32 rounded-full object-cover relative border-4 border-white shadow-md mx-auto"
                                    />
                                </div>
                                <h3 className="text-2xl font-bold text-gray-900">Akash Satyam</h3>
                                <p className="text-purple-600 font-medium mb-4">Co-Founder & COO</p>
                                <p className="text-gray-500 text-sm mb-6">Operations & Strategy</p>
                                <p className="text-gray-600 italic leading-relaxed">
                                    "We’re not just building a website; we’re building a support system that empowers students to make the right career choices with confidence."
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
        </div>
    );
};

export default About;
