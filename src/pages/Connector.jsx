import React, { useState } from 'react';
import { FaSearch, FaUserMd, FaUniversity, FaComments, FaArrowRight, FaChevronDown, FaChevronUp } from 'react-icons/fa';

const Connector = () => {
    const [searchTerm, setSearchTerm] = useState('');
    const [openFaqIndex, setOpenFaqIndex] = useState(null);

    const toggleFaq = (index) => {
        setOpenFaqIndex(openFaqIndex === index ? null : index);
    };

    const seniors = [
        {
            id: 1,
            name: "Dr. Aditi Sharma",
            college: "AIIMS, New Delhi",
            course: "MBBS",
            year: "3rd Year",
            image: "https://placehold.co/150x150/E15583/ffffff?text=AS",
            tags: ["Academics", "Research"]
        },
        {
            id: 2,
            name: "Rahul Verma",
            college: "KGMU, Lucknow",
            course: "MBBS",
            year: "Intern",
            image: "https://placehold.co/150x150/8361D0/ffffff?text=RV",
            tags: ["Hostel Life", "Sports"]
        },
        {
            id: 3,
            name: "Sneha Gupta",
            college: "Maulana Azad Medical College",
            course: "BDS",
            year: "2nd Year",
            image: "https://placehold.co/150x150/4ade80/ffffff?text=SG",
            tags: ["Campus", "Fest"]
        },
        {
            id: 4,
            name: "Vikram Singh",
            college: "BHU, Varanasi",
            course: "BAMS",
            year: "4th Year",
            image: "https://placehold.co/150x150/facc15/ffffff?text=VS",
            tags: ["Ayurveda", "Research"]
        },
        {
            id: 5,
            name: "Priya Patel",
            college: "BJ Medical College, Ahmedabad",
            course: "MBBS",
            year: "1st Year",
            image: "https://placehold.co/150x150/60a5fa/ffffff?text=PP",
            tags: ["Fresher Guide", "Ragging Free"]
        },
        {
            id: 6,
            name: "Amit Kumar",
            college: "Grant Medical College, Mumbai",
            course: "MBBS",
            year: "Final Year",
            image: "https://placehold.co/150x150/f472b6/ffffff?text=AK",
            tags: ["Clinical", "PG Prep"]
        }
    ];

    const features = [
        {
            icon: <FaComments />,
            title: "Real Insights",
            desc: "Get honest & unfiltered reviews about campus, hostel, and mess food direct from students."
        },
        {
            icon: <FaUserMd />,
            title: "Faculty Quality",
            desc: "Understand the teaching standards and patient load for better clinical exposure."
        },
        {
            icon: <FaUniversity />,
            title: "Hidden Costs",
            desc: "Know about bond details, hidden fees, and living expenses before you join."
        }
    ];

    const faqs = [
        {
            question: "Is this service free?",
            answer: "Browsing profiles is free. Connecting customized 1-on-1 sessions may have a nominal fee to respect the senior's time."
        },
        {
            question: "Are these real students?",
            answer: "Yes, all seniors listed on Sartha Connector are verified students of their respective colleges."
        },
        {
            question: "How does the connection work?",
            answer: "You can send a request to connect. Once accepted, you can chat or schedule a video call tailored to your queries."
        }
    ];

    const filteredSeniors = seniors.filter(senior =>
        senior.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        senior.college.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="font-sans min-h-screen bg-gray-50">
            {/* Hero Section */}
            <section className="relative bg-gradient-to-br from-[#1a1025] to-[#2d1b42] text-white py-20 lg:py-24">
                <div className="absolute inset-0 bg-[url('/src/assets/bg-pattern.webp')] opacity-5 mix-blend-overlay"></div>
                <div className="container mx-auto px-4 relative z-10 text-center">
                    <h1 className="text-4xl md:text-6xl font-extrabold mb-6">Sartha Connector</h1>
                    <p className="text-xl text-gray-300 max-w-2xl mx-auto mb-10">
                        Connect directly with current medical students for real, honest, and unfiltered college reviews.
                    </p>

                    {/* Search Bar */}
                    <div className="max-w-2xl mx-auto relative">
                        <input
                            type="text"
                            placeholder="Search by College or Student Name..."
                            className="w-full py-4 pl-12 pr-4 rounded-full bg-white/10 backdrop-blur-md border border-white/20 text-white placeholder-gray-300 focus:outline-none focus:ring-4 focus:ring-purple-500/30 shadow-xl"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                        <FaSearch className="absolute left-5 top-1/2 transform -translate-y-1/2 text-gray-400 text-xl" />
                    </div>
                </div>
            </section>

            {/* How it Works */}
            <section className="py-16 bg-white">
                <div className="container mx-auto px-4">
                    <div className="text-center mb-12">
                        <h2 className="text-3xl font-bold text-gray-900">Why Connect?</h2>
                        <div className="w-16 h-1 bg-gradient-to-r from-[#E15583] to-[#8361D0] mx-auto mt-4 rounded-full"></div>
                    </div>
                    <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
                        {features.map((item, index) => (
                            <div key={index} className="bg-gray-50 p-8 rounded-2xl hover:shadow-lg transition text-center border border-gray-100">
                                <div className="text-4xl text-[#8361D0] mb-4 flex justify-center">{item.icon}</div>
                                <h3 className="text-xl font-bold mb-3">{item.title}</h3>
                                <p className="text-gray-600">{item.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* Seniors Grid */}
            <section className="py-16 bg-gray-50">
                <div className="container mx-auto px-4">
                    <div className="text-center mb-12">
                        <h2 className="text-3xl font-bold text-gray-900">Find Your Seniors</h2>
                        <p className="text-gray-500 mt-2">Browse profiles from top medical colleges</p>
                    </div>

                    <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-6xl mx-auto">
                        {filteredSeniors.length > 0 ? (
                            filteredSeniors.map((senior) => (
                                <div key={senior.id} className="bg-white p-6 rounded-2xl shadow-sm hover:shadow-xl transition-all duration-300 border border-gray-100 flex flex-col items-center text-center group">
                                    <div className="relative mb-4">
                                        <div className="absolute inset-0 bg-gradient-to-r from-[#E15583] to-[#8361D0] rounded-full blur opacity-20 group-hover:opacity-40 transition"></div>
                                        <img
                                            src={senior.image}
                                            alt={senior.name}
                                            className="w-24 h-24 rounded-full object-cover relative z-10 border-4 border-white shadow-md"
                                        />
                                    </div>
                                    <h3 className="text-xl font-bold text-gray-900">{senior.name}</h3>
                                    <p className="text-[#8361D0] font-medium text-sm mb-1">{senior.college}</p>
                                    <p className="text-gray-500 text-xs uppercase tracking-wide mb-4">{senior.course} • {senior.year}</p>

                                    <div className="flex gap-2 flex-wrap justify-center mb-6">
                                        {senior.tags.map((tag, i) => (
                                            <span key={i} className="bg-purple-50 text-purple-600 text-[10px] font-bold px-2 py-1 rounded-full uppercase">
                                                {tag}
                                            </span>
                                        ))}
                                    </div>

                                    <button className="mt-auto w-full py-3 rounded-xl bg-gray-900 text-white font-bold hover:bg-gray-800 transition flex items-center justify-center gap-2 group-hover:bg-gradient-to-r group-hover:from-[#E15583] group-hover:to-[#8361D0]">
                                        Connect Now <FaArrowRight className="text-xs" />
                                    </button>
                                </div>
                            ))
                        ) : (
                            <div className="col-span-full text-center py-10">
                                <p className="text-gray-500 text-lg">No seniors found matching your search.</p>
                            </div>
                        )}
                    </div>
                </div>
            </section>

            {/* FAQ Section */}
            <section className="py-16 bg-white border-t border-gray-100">
                <div className="container mx-auto px-4 max-w-3xl">
                    <div className="text-center mb-12">
                        <h2 className="text-3xl font-bold text-gray-900">Frequently Asked Questions</h2>
                        <div className="w-16 h-1 bg-gradient-to-r from-[#E15583] to-[#8361D0] mx-auto mt-4 rounded-full"></div>
                    </div>

                    <div className="space-y-4">
                        {faqs.map((faq, index) => (
                            <div
                                key={index}
                                className="border border-gray-200 rounded-xl overflow-hidden hover:border-purple-200 transition duration-300"
                            >
                                <button
                                    className="w-full flex justify-between items-center p-5 bg-gray-50 hover:bg-white text-left focus:outline-none transition-colors duration-300"
                                    onClick={() => toggleFaq(index)}
                                >
                                    <span className="font-semibold text-gray-900 text-lg">{faq.question}</span>
                                    {openFaqIndex === index ? (
                                        <FaChevronUp className="text-[#8361D0]" />
                                    ) : (
                                        <FaChevronDown className="text-gray-400" />
                                    )}
                                </button>
                                <div
                                    className={`overflow-hidden transition-all duration-300 ease-in-out ${openFaqIndex === index ? 'max-h-40 opacity-100' : 'max-h-0 opacity-0'}`}
                                >
                                    <div className="p-5 pt-0 text-gray-600 leading-relaxed border-t border-gray-100 bg-white">
                                        <div className="pt-4">{faq.answer}</div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </section>
        </div>
    );
};

export default Connector;
