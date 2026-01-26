import React from 'react';
import { Link } from 'react-router-dom';
import { FaFilePdf, FaCheckCircle, FaUserGraduate, FaHandshake, FaTelegramPlane } from 'react-icons/fa';
import { BsArrowRight } from 'react-icons/bs';

const Predictor = () => {
    return (
        <div className="font-sans">
            {/* Hero Section */}
            <section className="relative bg-gradient-to-r from-gray-900 via-[#2A1B3D] to-gray-900 text-white py-20 lg:py-32 overflow-hidden">
                <div className="absolute inset-0 bg-[url('/assets/bg-pattern.webp')] opacity-10 mix-blend-overlay"></div>
                <div className="container mx-auto px-4 relative z-10 text-center">
                    <h1 className="text-4xl md:text-6xl font-bold mb-6">
                        Find the Right College <br />
                        <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#E15583] to-[#8361D0]">
                            Smarter, Faster, Verified
                        </span>
                    </h1>
                    <p className="text-xl md:text-2xl text-gray-300 mb-10 max-w-3xl mx-auto">
                        AI-powered predictor for NEET UG & NEET PG with 100+ parameters, verified datasets, and instant PDF reports.
                    </p>
                    <div className="flex flex-col sm:flex-row justify-center gap-4">
                        <a
                            href="#predictors"
                            className="bg-gradient-to-r from-[#E15583] to-[#8361D0] hover:shadow-lg hover:shadow-primary-purple/50 text-white px-8 py-4 rounded-full font-bold text-lg transition transform hover:-translate-y-1"
                        >
                            Explore Predictors
                        </a>
                        <a
                            href="#how-it-works"
                            className="bg-white/10 backdrop-blur-sm border border-white/20 hover:bg-white/20 text-white px-8 py-4 rounded-full font-bold text-lg transition"
                        >
                            See How It Works
                        </a>
                    </div>
                </div>
            </section>

            {/* Predictors Section */}
            <section id="predictors" className="py-20 bg-gray-50">
                <div className="container mx-auto px-4">
                    <div className="grid md:grid-cols-2 gap-10 max-w-6xl mx-auto">

                        {/* NEET UG Card */}
                        <div className="bg-white rounded-3xl shadow-xl overflow-hidden hover:shadow-2xl transition-shadow duration-300 border border-gray-100">
                            <div className="h-48 bg-gradient-to-br from-blue-50 to-indigo-50 flex items-center justify-center p-6">
                                <img src="/assets/medical-girl.png" alt="NEET UG" className="h-full object-contain drop-shadow-md" />
                            </div>
                            <div className="p-8">
                                <div className="flex justify-between items-start mb-4">
                                    <h3 className="text-2xl font-bold text-gray-900">NEET UG Predictor</h3>
                                    <span className="bg-blue-100 text-blue-800 text-xs font-semibold px-3 py-1 rounded-full uppercase tracking-wide">MBBS & Dental</span>
                                </div>
                                <ul className="space-y-3 mb-8 text-gray-600">
                                    <li className="flex items-start gap-2">
                                        <FaCheckCircle className="text-green-500 mt-1 flex-shrink-0" />
                                        <span>MBBS & BDS across AIQ, State, Deemed, Private, Minority quotas</span>
                                    </li>
                                    <li className="flex items-start gap-2">
                                        <FaCheckCircle className="text-green-500 mt-1 flex-shrink-0" />
                                        <span>Category-wise, round-wise cut-offs & trend awareness</span>
                                    </li>
                                    <li className="flex items-start gap-2">
                                        <FaCheckCircle className="text-green-500 mt-1 flex-shrink-0" />
                                        <span>Personalized college shortlist with seat & fee info</span>
                                    </li>
                                </ul>
                                <div className="flex flex-col gap-3">
                                    <Link to="/predictor-neet-ug" className="w-full bg-[#8361D0] hover:bg-[#6c4ab6] text-white py-3 rounded-xl font-bold transition flex items-center justify-center gap-2">
                                        Get UG Report <BsArrowRight />
                                    </Link>
                                    <a href="https://sartha.in/pdf/Sample_Report_UG.pdf" target="_blank" rel="noreferrer" className="w-full text-gray-500 hover:text-[#8361D0] text-sm font-medium flex items-center justify-center gap-2 transition">
                                        <FaFilePdf /> View Sample Report
                                    </a>
                                </div>
                            </div>
                        </div>

                        {/* NEET PG Card */}
                        <div className="bg-white rounded-3xl shadow-xl overflow-hidden hover:shadow-2xl transition-shadow duration-300 border border-gray-100">
                            <div className="h-48 bg-gradient-to-br from-pink-50 to-rose-50 flex items-center justify-center p-6">
                                <img src="/assets/predictor-tool.png" alt="NEET PG" className="h-full object-contain drop-shadow-md" />
                            </div>
                            <div className="p-8">
                                <div className="flex justify-between items-start mb-4">
                                    <h3 className="text-2xl font-bold text-gray-900">NEET PG Predictor</h3>
                                    <span className="bg-pink-100 text-pink-800 text-xs font-semibold px-3 py-1 rounded-full uppercase tracking-wide">MD, MS & DNB</span>
                                </div>
                                <ul className="space-y-3 mb-8 text-gray-600">
                                    <li className="flex items-start gap-2">
                                        <FaCheckCircle className="text-green-500 mt-1 flex-shrink-0" />
                                        <span>Branch-wise insights for MD/MS/DNB/Diploma</span>
                                    </li>
                                    <li className="flex items-start gap-2">
                                        <FaCheckCircle className="text-green-500 mt-1 flex-shrink-0" />
                                        <span>MCC + State counselling options, quota & bond filters</span>
                                    </li>
                                    <li className="flex items-start gap-2">
                                        <FaCheckCircle className="text-green-500 mt-1 flex-shrink-0" />
                                        <span>Instant downloadable report with cut-off mapping, Stipend, Fee, Bond</span>
                                    </li>
                                </ul>
                                <div className="flex flex-col gap-3">
                                    <Link to="/neet-pg-preference-list" className="w-full bg-[#E15583] hover:bg-[#c93d6e] text-white py-3 rounded-xl font-bold transition flex items-center justify-center gap-2">
                                        Get PG Report <BsArrowRight />
                                    </Link>
                                    <a href="https://sartha.in/pdf/Sample_Report_PG.pdf" target="_blank" rel="noreferrer" className="w-full text-gray-500 hover:text-[#E15583] text-sm font-medium flex items-center justify-center gap-2 transition">
                                        <FaFilePdf /> View Sample Report
                                    </a>
                                </div>
                            </div>
                        </div>

                    </div>
                </div>
            </section>

            {/* How It Works Section */}
            <section id="how-it-works" className="py-20 bg-white">
                <div className="container mx-auto px-4">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">How it works</h2>
                        <p className="text-gray-500 max-w-2xl mx-auto">Get your personalized college prediction report in 4 simple steps.</p>
                    </div>

                    <div className="grid md:grid-cols-4 gap-8 max-w-6xl mx-auto">
                        {[
                            { step: "01", title: "Pick Path", desc: "Select counselling type (UG/PG) and your preferences." },
                            { step: "02", title: "Input Details", desc: "Enter your Rank, Category, Quota & other specific details." },
                            { step: "03", title: "Secure Account", desc: "Create an account and complete the secure payment." },
                            { step: "04", title: "Download PDF", desc: "Instantly download your personalized college list report." }
                        ].map((item, index) => (
                            <div key={index} className="relative p-6 rounded-2xl bg-gray-50 hover:bg-white hover:shadow-xl transition-all duration-300 border border-gray-100 group">
                                <div className="text-5xl font-black text-gray-200 mb-4 group-hover:text-primary-pink/20 transition-colors">{item.step}</div>
                                <h3 className="text-xl font-bold text-gray-900 mb-3">{item.title}</h3>
                                <p className="text-gray-500 text-sm leading-relaxed">{item.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* Why Sartha Section */}
            <section className="py-20 bg-gray-900 text-white">
                <div className="container mx-auto px-4">
                    <div className="grid md:grid-cols-2 gap-12 items-center max-w-6xl mx-auto">
                        <div>
                            <h2 className="text-3xl md:text-4xl font-bold mb-6">Why SARTHA Predictor?</h2>
                            <div className="space-y-6">
                                {[
                                    "Trusted by thousands of users",
                                    "Detailed round-wise cutoffs & audit trail",
                                    "Smooth experience on phones & tablets",
                                    "One click instant download",
                                    "Verified by Experienced Counselors, Professors & HODs"
                                ].map((feature, i) => (
                                    <div key={i} className="flex items-center gap-4 p-4 bg-white/5 rounded-xl border border-white/10 hover:border-primary-purple/50 transition">
                                        <div className="bg-gradient-to-br from-[#E15583] to-[#8361D0] p-2 rounded-full">
                                            <FaCheckCircle className="text-white text-lg" />
                                        </div>
                                        <span className="font-medium text-lg text-gray-200">{feature}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                        <div className="hidden md:flex justify-center">
                            {/* Abstract Visual or Illustration */}
                            <div className="relative w-80 h-96 bg-gradient-to-tr from-[#E15583] to-[#8361D0] rounded-full blur-3xl opacity-20 animate-pulse"></div>
                            <img src="/assets/connector-illo.png" alt="Analytics" className="relative z-10 w-full max-w-md drop-shadow-2xl hover:scale-105 transition duration-500" />
                        </div>
                    </div>
                </div>
            </section>

            {/* Join Us / CTA Section */}
            <section className="py-20 bg-gray-50">
                <div className="container mx-auto px-4">
                    <div className="text-center mb-12">
                        <h2 className="text-3xl font-bold text-gray-900">Join our Community</h2>
                    </div>
                    <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">

                        {/* Ambassador */}
                        <div className="bg-white p-8 rounded-2xl shadow-sm hover:shadow-md transition border border-gray-100 text-center">
                            <div className="w-16 h-16 bg-blue-50 text-blue-600 rounded-full flex items-center justify-center mx-auto mb-6 text-2xl">
                                <FaUserGraduate />
                            </div>
                            <h3 className="text-xl font-bold mb-3">Become an Ambassador</h3>
                            <p className="text-gray-500 text-sm mb-6">If you believe in Sartha, like we do, become an ambassador.</p>
                            <a href="https://docs.google.com/forms/d/e/1FAIpQLSdyy3zSINgEooWoRaitinzHNFXEnPD0ZTA7vqMHX4BNEGRNZA/viewform" target="_blank" rel="noreferrer" className="text-blue-600 font-semibold hover:underline">Fill Form &rarr;</a>
                        </div>

                        {/* Collab */}
                        <div className="bg-white p-8 rounded-2xl shadow-sm hover:shadow-md transition border border-gray-100 text-center">
                            <div className="w-16 h-16 bg-purple-50 text-purple-600 rounded-full flex items-center justify-center mx-auto mb-6 text-2xl">
                                <FaHandshake />
                            </div>
                            <h3 className="text-xl font-bold mb-3">Collab With Us</h3>
                            <p className="text-gray-500 text-sm mb-6">Bring a revolution in the field of counselling by collaborating.</p>
                            <a href="https://forms.gle/cZ1TatPCc67o2aKs6" target="_blank" rel="noreferrer" className="text-purple-600 font-semibold hover:underline">Collaborate Now &rarr;</a>
                        </div>

                        {/* Telegram */}
                        <div className="bg-white p-8 rounded-2xl shadow-sm hover:shadow-md transition border border-gray-100 text-center">
                            <div className="w-16 h-16 bg-sky-50 text-sky-600 rounded-full flex items-center justify-center mx-auto mb-6 text-2xl">
                                <FaTelegramPlane />
                            </div>
                            <h3 className="text-xl font-bold mb-3">Join Telegram</h3>
                            <p className="text-gray-500 text-sm mb-6">For latest updates, notifications and counselling alerts.</p>
                            <a href="https://t.me/ncertmorise" target="_blank" rel="noreferrer" className="text-sky-600 font-semibold hover:underline">Join Channel &rarr;</a>
                        </div>

                    </div>
                </div>
            </section>
        </div>
    );
};

export default Predictor;
