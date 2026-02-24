import React from 'react';
import { FaUniversity, FaBuilding, FaBook, FaPassport, FaUserShield, FaChalkboardTeacher, FaLandmark, FaUserNurse } from 'react-icons/fa';

const Courses = () => {
    return (
        <div className="font-sans">
            {/* Hero Section */}
            <section className="relative bg-gradient-to-r from-gray-900 via-[#1e1b4b] to-gray-900 text-white py-20 lg:py-28 overflow-hidden">
                <div className="absolute inset-0 bg-[url('/assets/bg-pattern.webp')] opacity-10 mix-blend-overlay"></div>

                <div className="container mx-auto px-4 relative z-10 text-center">
                    <h1 className="text-4xl md:text-6xl font-bold mb-6">
                        Competitive Exam Guidance <br />
                        <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-teal-400">
                            (Central + State Government)
                        </span>
                    </h1>
                    <p className="text-xl md:text-2xl text-gray-300 mb-8 max-w-3xl mx-auto">
                        NextStep Counsel is not limited to medical admissions — we also support aspirants preparing for all major competitive exams.
                    </p>
                </div>
            </section>

            {/* Central Government Exams */}
            <section className="py-20 bg-gray-50">
                <div className="container mx-auto px-4">
                    <div className="flex items-center justify-center gap-4 mb-12">
                        <div className="p-3 bg-blue-100 rounded-full text-blue-600"><FaLandmark size={24} /></div>
                        <h2 className="text-3xl font-bold text-gray-900">Central Government Exams</h2>
                    </div>

                    <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-6xl mx-auto">

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition">
                            <h3 className="text-xl font-bold text-gray-800 mb-3 flex items-center gap-2">
                                <span className="w-2 h-8 bg-blue-500 rounded-full"></span> UPSC
                            </h3>
                            <ul className="text-gray-600 space-y-2 ml-4 list-disc list-inside">
                                <li>Civil Services (IAS, IPS, IFS)</li>
                                <li>NDA (National Defence Academy)</li>
                                <li>CDS (Combined Defence Services)</li>
                            </ul>
                        </div>

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition">
                            <h3 className="text-xl font-bold text-gray-800 mb-3 flex items-center gap-2">
                                <span className="w-2 h-8 bg-green-500 rounded-full"></span> SSC
                            </h3>
                            <ul className="text-gray-600 space-y-2 ml-4 list-disc list-inside">
                                <li>CGL (Combined Graduate Level)</li>
                                <li>CHSL (Combined Higher Secondary)</li>
                                <li>GD Constable</li>
                                <li>MTS (Multi Tasking Staff)</li>
                            </ul>
                        </div>

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition">
                            <h3 className="text-xl font-bold text-gray-800 mb-3 flex items-center gap-2">
                                <span className="w-2 h-8 bg-indigo-500 rounded-full"></span> Railway Exams
                            </h3>
                            <ul className="text-gray-600 space-y-2 ml-4 list-disc list-inside">
                                <li>RRB NTPC</li>
                                <li>RRB Group D</li>
                                <li>RRB ALP/Technician</li>
                            </ul>
                        </div>

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition">
                            <h3 className="text-xl font-bold text-gray-800 mb-3 flex items-center gap-2">
                                <span className="w-2 h-8 bg-orange-500 rounded-full"></span> Banking Exams
                            </h3>
                            <ul className="text-gray-600 space-y-2 ml-4 list-disc list-inside">
                                <li>IBPS PO / Clerk</li>
                                <li>SBI PO / Clerk</li>
                                <li>RBI Grade B / Assistant</li>
                            </ul>
                        </div>

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition">
                            <h3 className="text-xl font-bold text-gray-800 mb-3 flex items-center gap-2">
                                <span className="w-2 h-8 bg-red-500 rounded-full"></span> Defence Exams
                            </h3>
                            <ul className="text-gray-600 space-y-2 ml-4 list-disc list-inside">
                                <li>Army / Navy / Airforce</li>
                                <li>AFCAT</li>
                                <li>CAPF (Assistant Commandant)</li>
                            </ul>
                        </div>

                        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition">
                            <h3 className="text-xl font-bold text-gray-800 mb-3 flex items-center gap-2">
                                <span className="w-2 h-8 bg-yellow-500 rounded-full"></span> Teaching Exams
                            </h3>
                            <ul className="text-gray-600 space-y-2 ml-4 list-disc list-inside">
                                <li>CTET (Central Teacher Eligibility)</li>
                                <li>KVS (Kendriya Vidyalaya)</li>
                                <li>NVS (Navodaya Vidyalaya)</li>
                            </ul>
                        </div>

                    </div>
                </div>
            </section>

            {/* State Government Exams */}
            <section className="py-20 bg-white">
                <div className="container mx-auto px-4">
                    <div className="flex items-center justify-center gap-4 mb-12">
                        <div className="p-3 bg-purple-100 rounded-full text-purple-600"><FaBuilding size={24} /></div>
                        <h2 className="text-3xl font-bold text-gray-900">State Government Exams</h2>
                    </div>

                    <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-6xl mx-auto">

                        <div className="p-6 rounded-xl bg-gray-50 border border-gray-200 hover:border-purple-300 transition group">
                            <div className="w-12 h-12 bg-white rounded-lg shadow-sm flex items-center justify-center text-purple-600 mb-4 group-hover:scale-110 transition"><FaPassport /></div>
                            <h3 className="text-lg font-bold mb-2">State PSC Exams</h3>
                            <p className="text-gray-500 text-sm">Preparation for Public Service Commission exams of various states.</p>
                        </div>

                        <div className="p-6 rounded-xl bg-gray-50 border border-gray-200 hover:border-purple-300 transition group">
                            <div className="w-12 h-12 bg-white rounded-lg shadow-sm flex items-center justify-center text-purple-600 mb-4 group-hover:scale-110 transition"><FaUserShield /></div>
                            <h3 className="text-lg font-bold mb-2">Police & SI Recruitment</h3>
                            <p className="text-gray-500 text-sm">State Police Constable, Sub-Inspector and other uniformed services.</p>
                        </div>

                        <div className="p-6 rounded-xl bg-gray-50 border border-gray-200 hover:border-purple-300 transition group">
                            <div className="w-12 h-12 bg-white rounded-lg shadow-sm flex items-center justify-center text-purple-600 mb-4 group-hover:scale-110 transition"><FaBook /></div>
                            <h3 className="text-lg font-bold mb-2">Patwari & Revenue</h3>
                            <p className="text-gray-500 text-sm">Exams for Patwari, Revenue Inspector, and Village Development Officers.</p>
                        </div>

                        <div className="p-6 rounded-xl bg-gray-50 border border-gray-200 hover:border-purple-300 transition group">
                            <div className="w-12 h-12 bg-white rounded-lg shadow-sm flex items-center justify-center text-purple-600 mb-4 group-hover:scale-110 transition"><FaBuilding /></div>
                            <h3 className="text-lg font-bold mb-2">State SSC & Clerk</h3>
                            <p className="text-gray-500 text-sm">Lower Division Clerk (LDC), UDC, and State Staff Selection Commission exams.</p>
                        </div>

                        <div className="p-6 rounded-xl bg-gray-50 border border-gray-200 hover:border-purple-300 transition group">
                            <div className="w-12 h-12 bg-white rounded-lg shadow-sm flex items-center justify-center text-purple-600 mb-4 group-hover:scale-110 transition"><FaUserNurse /></div>
                            <h3 className="text-lg font-bold mb-2">Nursing & Paramedical</h3>
                            <p className="text-gray-500 text-sm">State-level Nursing Staff, ANM/GNM, and Paramedical recruitment tests.</p>
                        </div>

                        <div className="p-6 rounded-xl bg-gray-50 border border-gray-200 hover:border-purple-300 transition group">
                            <div className="w-12 h-12 bg-white rounded-lg shadow-sm flex items-center justify-center text-purple-600 mb-4 group-hover:scale-110 transition"><FaChalkboardTeacher /></div>
                            <h3 className="text-lg font-bold mb-2">State TET Exams</h3>
                            <p className="text-gray-500 text-sm">Teacher Eligibility Tests (REET, UPTET, MPTET, etc.) for state schools.</p>
                        </div>

                    </div>
                </div>
            </section>

            {/* Resources Support CTA */}
            <section className="py-20 bg-gradient-to-br from-indigo-900 to-blue-900 text-white text-center">
                <div className="container mx-auto px-4">
                    <h2 className="text-3xl font-bold mb-6">Structured Guidance & Resources</h2>
                    <p className="text-xl text-blue-200 mb-10 max-w-2xl mx-auto">
                        No matter the exam, we provide updated notifications, study strategy, and expert mentorship for long-term success.
                    </p>
                    <div className="flex flex-col sm:flex-row justify-center gap-4">
                        <a href="https://wa.me/919588928940" target="_blank" rel="noreferrer" className="bg-green-500 hover:bg-green-600 text-white px-8 py-3 rounded-full font-bold transition shadow-lg">
                            Get Guidance on WhatsApp
                        </a>
                    </div>
                </div>
            </section>
        </div>
    );
};

export default Courses;
