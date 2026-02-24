import React from 'react';
import { FaBook, FaArrowRight, FaCloudDownloadAlt, FaRegFilePdf } from 'react-icons/fa';
import { Link } from 'react-router-dom';

const EBooksSection = () => {
    return (
        <section className="py-24 bg-white relative">
            <div className="container mx-auto px-4 flex flex-col md:flex-row items-center gap-16">
                <div className="md:w-1/2">
                    <div className="inline-block bg-orange-100 text-orange-600 px-4 py-1.5 rounded-full font-bold text-sm mb-6 uppercase tracking-wide">
                        Knowledge Base
                    </div>
                    <h2 className="text-4xl md:text-5xl font-extrabold mb-6 text-gray-900">
                        Counselling <span className="text-transparent bg-clip-text bg-gradient-to-r from-orange-500 to-red-500">eBooks</span>
                    </h2>
                    <p className="text-gray-600 mb-10 text-lg leading-relaxed">
                        Comprehensive guides containing everything you need to know about medical counselling, seat matrices, fee structures, and bond details.
                    </p>

                    <div className="grid grid-cols-1 gap-3 mb-10">
                        {[
                            "Round-wise NEET Cut-off (2023-2025) for MCC All India Quota & State Quota",
                            "Fees Structure of all Colleges",
                            "Top Ranking General/Common Preference List",
                            "Counselling Rules of MCC All India & All States (Information Bulletin/Brochure)",
                            "State Bond Details",
                            "Notification through WhatsApp Community",
                            "Counselling & Domicile Rules for all States"
                        ].map((item, i) => (
                            <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-orange-50/50 border border-orange-100 hover:bg-orange-50 transition">
                                <div className="bg-white p-1.5 rounded shadow-sm text-orange-500 mt-0.5 flex-shrink-0"><FaBook size={12} /></div>
                                <span className="font-medium text-gray-700 text-sm">{item}</span>
                            </div>
                        ))}
                    </div>

                    <Link to="/ebooks" className="inline-flex bg-gradient-to-r from-orange-500 to-red-500 text-white px-8 py-4 rounded-full font-bold items-center gap-2 hover:shadow-lg hover:shadow-orange-200 hover:-translate-y-1 transition transform">
                        <FaCloudDownloadAlt /> View Library <FaArrowRight />
                    </Link>
                </div>
                <div className="md:w-1/2 flex justify-center relative group">
                    <div className="absolute inset-0 bg-orange-200 rounded-full blur-[100px] opacity-30 group-hover:opacity-50 transition duration-700"></div>
                    <img src="/assets/ebook-cover.png" alt="Counselling eBooks" className="w-full max-w-lg relative z-10 drop-shadow-2xl transform group-hover:rotate-3 group-hover:scale-105 transition duration-500" />
                </div>
            </div>
        </section>
    );
};

export default EBooksSection;
