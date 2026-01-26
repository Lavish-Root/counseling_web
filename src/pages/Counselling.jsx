import React from 'react';
import { Link } from 'react-router-dom';
import { FaStethoscope, FaTooth, FaLeaf, FaPaw, FaUniversity, FaDownload, FaArrowRight, FaUserGraduate, FaHandshake, FaTelegramPlane } from 'react-icons/fa';

const Counselling = () => {
    const services = [
        {
            title: "MBBS Counselling",
            subtitle: "Medical",
            icon: <FaStethoscope />,
            link: "/counselling/mbbs",
            color: "from-blue-500 to-cyan-500",
            bg: "bg-blue-50 text-blue-600"
        },
        {
            title: "BDS Counselling",
            subtitle: "Dental",
            icon: <FaTooth />,
            link: "/counselling/bds",
            color: "from-teal-500 to-emerald-500",
            bg: "bg-teal-50 text-teal-600"
        },
        {
            title: "AYUSH Counselling",
            subtitle: "Ayu, Homeo, Unani",
            icon: <FaLeaf />,
            link: "/counselling/ayush",
            color: "from-green-500 to-lime-500",
            bg: "bg-green-50 text-green-600"
        },
        {
            title: "BVSC & AH Counselling",
            subtitle: "Veterinary",
            icon: <FaPaw />,
            link: "/counselling/bvsc-ah",
            color: "from-orange-500 to-amber-500",
            bg: "bg-orange-50 text-orange-600"
        },
        {
            title: "CUET Counselling",
            subtitle: "Central Universities",
            icon: <FaUniversity />,
            link: "/counselling/cuet",
            color: "from-pink-500 to-rose-500",
            bg: "bg-pink-50 text-pink-600"
        }
    ];

    return (
        <div className="font-sans">
            {/* Hero Section */}
            <section className="relative bg-gradient-to-br from-gray-900 via-[#1a1025] to-gray-900 text-white py-24 lg:py-32 overflow-hidden">
                <div className="absolute inset-0 bg-[url('/src/assets/bg-pattern.webp')] opacity-10 mix-blend-overlay"></div>
                <div className="absolute top-0 right-0 w-96 h-96 bg-[#E15583] rounded-full blur-[100px] opacity-20 translate-x-1/2 -translate-y-1/2"></div>
                <div className="absolute bottom-0 left-0 w-96 h-96 bg-[#8361D0] rounded-full blur-[100px] opacity-20 -translate-x-1/2 translate-y-1/2"></div>

                <div className="container mx-auto px-4 relative z-10 text-center">
                    <h1 className="text-4xl md:text-6xl font-extrabold mb-6 leading-tight">
                        Your One-Stop Solution for <br />
                        <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#E15583] to-[#8361D0]">
                            all type of College Counselling
                        </span>
                    </h1>
                    <p className="text-lg md:text-xl text-gray-300 mb-8 font-medium tracking-wide">
                        MBBS • BDS • AYUSH • BVSc & AH • CUET
                    </p>

                    <a
                        href="https://drive.google.com/file/d/1Gj8t2x-jO-WYgJWokdrwzBEQkwzGlGmi/view"
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-3 bg-white text-gray-900 hover:bg-gray-100 px-8 py-4 rounded-full font-bold text-lg transition transform hover:-translate-y-1 shadow-lg shadow-white/10"
                    >
                        <FaDownload /> Download Brochure
                    </a>
                </div>
            </section>

            {/* Services Grid */}
            <section className="py-20 bg-gray-50">
                <div className="container mx-auto px-4">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl font-bold text-gray-900">Choose Your Counseling Path</h2>
                        <div className="w-20 h-1 bg-gradient-to-r from-[#E15583] to-[#8361D0] mx-auto mt-4 rounded-full"></div>
                    </div>

                    <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-6xl mx-auto">
                        {services.map((service, index) => (
                            <Link
                                key={index}
                                to={service.link}
                                className="group relative bg-white rounded-2xl shadow-sm hover:shadow-xl transition-all duration-300 border border-gray-100 overflow-hidden"
                            >
                                <div className={`h-2 w-full bg-gradient-to-r ${service.color}`}></div>
                                <div className="p-8">
                                    <div className={`w-14 h-14 ${service.bg} rounded-xl flex items-center justify-center text-2xl mb-6 group-hover:scale-110 transition-transform duration-300`}>
                                        {service.icon}
                                    </div>
                                    <h3 className="text-xl font-bold text-gray-900 mb-1 group-hover:text-[#8361D0] transition-colors">{service.title}</h3>
                                    <p className="text-gray-500 text-sm font-medium uppercase tracking-wider mb-6">{service.subtitle}</p>

                                    <div className="flex items-center text-sm font-bold text-gray-400 group-hover:text-gray-900 transition-colors">
                                        Explore <FaArrowRight className="ml-2 transform group-hover:translate-x-1 transition-transform" />
                                    </div>
                                </div>
                            </Link>
                        ))}
                    </div>
                </div>
            </section>

            {/* Join Us / CTA Section (Reused from Predictor for consistency) */}
            <section className="py-20 bg-white border-t border-gray-100">
                <div className="container mx-auto px-4">
                    <div className="text-center mb-12">
                        <h2 className="text-3xl font-bold text-gray-900">Join our Community</h2>
                    </div>
                    <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">

                        {/* Ambassador */}
                        <div className="bg-gray-50 p-8 rounded-2xl shadow-sm hover:shadow-md transition border border-gray-100 text-center">
                            <div className="w-16 h-16 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center mx-auto mb-6 text-2xl">
                                <FaUserGraduate />
                            </div>
                            <h3 className="text-xl font-bold mb-3">Become an Ambassador</h3>
                            <p className="text-gray-500 text-sm mb-6">If you believe in Sartha, like we do, become an ambassador.</p>
                            <a href="https://docs.google.com/forms/d/e/1FAIpQLSdyy3zSINgEooWoRaitinzHNFXEnPD0ZTA7vqMHX4BNEGRNZA/viewform" target="_blank" rel="noreferrer" className="text-blue-600 font-semibold hover:underline">Fill Form &rarr;</a>
                        </div>

                        {/* Collab */}
                        <div className="bg-gray-50 p-8 rounded-2xl shadow-sm hover:shadow-md transition border border-gray-100 text-center">
                            <div className="w-16 h-16 bg-purple-100 text-purple-600 rounded-full flex items-center justify-center mx-auto mb-6 text-2xl">
                                <FaHandshake />
                            </div>
                            <h3 className="text-xl font-bold mb-3">Collab With Us</h3>
                            <p className="text-gray-500 text-sm mb-6">Bring a revolution in the field of counselling by collaborating.</p>
                            <a href="https://forms.gle/cZ1TatPCc67o2aKs6" target="_blank" rel="noreferrer" className="text-purple-600 font-semibold hover:underline">Collaborate Now &rarr;</a>
                        </div>

                        {/* Telegram */}
                        <div className="bg-gray-50 p-8 rounded-2xl shadow-sm hover:shadow-md transition border border-gray-100 text-center">
                            <div className="w-16 h-16 bg-sky-100 text-sky-600 rounded-full flex items-center justify-center mx-auto mb-6 text-2xl">
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

export default Counselling;
