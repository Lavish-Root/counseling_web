import React from 'react';
import { FaCalendarAlt, FaUser, FaArrowRight, FaTag, FaYoutube, FaPlay } from 'react-icons/fa';

const Blogs = () => {
    const blogs = [
        {
            id: 1,
            title: "NEET UG 2025: Key Changes You Should Know",
            excerpt: "NTA has announced major updates for the upcoming NEET exam. From syllabus revisions to exam pattern tweaks, here's everything you need to prepare effectively.",
            date: "Jan 15, 2025",
            author: "Dr. Jayesh Ghanchi",
            category: "Exam Updates",
            image: "https://placehold.co/600x400/E15583/ffffff?text=NEET+2025"
        },
        {
            id: 2,
            title: "Government vs Private Medical Colleges: Making the Choice",
            excerpt: "Struggling to decide? We break down the fee structures, patient load, faculty quality, and internship opportunities to help you make an informed decision.",
            date: "Jan 10, 2025",
            author: "Team NextStep Counsel",
            category: "Counselling Guide",
            image: "https://placehold.co/600x400/8361D0/ffffff?text=Govt+vs+Pvt"
        },
        {
            id: 3,
            title: "The Ultimate Document Checklist for Counselling",
            excerpt: "Don't let a missing document cost you a seat. Save this complete checklist of certificates required for All India and State Quota counselling.",
            date: "Jan 05, 2025",
            author: "Akash Satyam",
            category: "Admissions",
            image: "https://placehold.co/600x400/4ade80/ffffff?text=Documents"
        },
        {
            id: 4,
            title: "Ayush vs MBBS: Career Scope and Opportunities",
            excerpt: "Is BAMS or BHMS a good alternative to MBBS? Explore the growing scope of AYUSH medicine in India and abroad.",
            date: "Dec 28, 2024",
            author: "Dr. Aditi",
            category: "Career Guidance",
            image: "https://placehold.co/600x400/facc15/ffffff?text=AYUSH+Career"
        },
        {
            id: 5,
            title: "Top 10 Medical Colleges in India (NIRF Rankings)",
            excerpt: "A deep dive into the best medical institutes in India based on infrastructure, research, and placement records.",
            date: "Dec 20, 2024",
            author: "Team NextStep Counsel",
            category: "College Reviews",
            image: "https://placehold.co/600x400/60a5fa/ffffff?text=Top+10+Colleges"
        },
        {
            id: 6,
            title: "Understanding the MCC Counselling Process",
            excerpt: "Confused about rounds? We explain the flow of AIQ Round 1, Round 2, Mop-up, and Stray Vacancy rounds in simple terms.",
            date: "Dec 12, 2024",
            author: "Counselling Expert",
            category: "Counselling Guide",
            image: "https://placehold.co/600x400/f472b6/ffffff?text=MCC+Process"
        }
    ];

    return (
        <div className="font-sans min-h-screen bg-gray-50">
            {/* Hero Section */}
            <section className="relative bg-gradient-to-r from-[#1a1025] to-[#2d1b42] text-white py-20 lg:py-28">
                <div className="absolute inset-0 bg-[url('/assets/bg-pattern.webp')] opacity-5 mix-blend-overlay"></div>
                <div className="container mx-auto px-4 relative z-10 text-center">
                    <h1 className="text-4xl md:text-5xl font-bold mb-4">News, Blogs & Articles</h1>
                    <p className="text-xl text-gray-300 max-w-3xl mx-auto">
                        Your go-to resource for the latest updates on exams, college admissions, and counselling insights.
                    </p>
                </div>
            </section>

            {/* Blogs Grid */}
            <section className="py-16">
                <div className="container mx-auto px-4">
                    <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-7xl mx-auto">
                        {blogs.map((blog) => (
                            <div
                                key={blog.id}
                                className="bg-white rounded-2xl shadow-sm hover:shadow-xl transition-all duration-300 overflow-hidden flex flex-col h-full border border-gray-100 group"
                            >
                                <div className="relative overflow-hidden h-56">
                                    <div className="absolute top-4 left-4 z-10">
                                        <span className="bg-white/90 backdrop-blur-sm text-[#8361D0] text-xs font-bold px-3 py-1 rounded-full flex items-center gap-1 shadow-sm">
                                            <FaTag size={10} /> {blog.category}
                                        </span>
                                    </div>
                                    <img
                                        src={blog.image}
                                        alt={blog.title}
                                        className="w-full h-full object-cover transform group-hover:scale-110 transition-transform duration-700"
                                    />
                                    <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                                </div>

                                <div className="p-6 flex-grow flex flex-col">
                                    <div className="flex items-center text-gray-400 text-xs mb-3 gap-4">
                                        <div className="flex items-center gap-1">
                                            <FaCalendarAlt /> {blog.date}
                                        </div>
                                        <div className="flex items-center gap-1">
                                            <FaUser /> {blog.author}
                                        </div>
                                    </div>

                                    <h3 className="text-xl font-bold text-gray-900 mb-3 line-clamp-2 group-hover:text-[#E15583] transition-colors">
                                        {blog.title}
                                    </h3>
                                    <p className="text-gray-600 text-sm leading-relaxed mb-4 line-clamp-3">
                                        {blog.excerpt}
                                    </p>

                                    <div className="mt-auto">
                                        <button className="text-[#8361D0] font-bold text-sm flex items-center gap-2 group-hover:gap-3 transition-all">
                                            Read Article <FaArrowRight />
                                        </button>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* YouTube Videos Section */}
                    <div className="mt-20 mb-10">
                        <div className="flex items-center gap-3 mb-8 justify-center">
                            <div className="bg-red-100 p-3 rounded-full text-red-600">
                                <FaYoutube size={24} />
                            </div>
                            <h2 className="text-3xl font-bold text-gray-900">Featured Videos</h2>
                        </div>

                        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-7xl mx-auto">
                            {[
                                {
                                    id: 1,
                                    title: "NEET 2025 Strategy | How to Score 650+",
                                    thumbnail: "https://placehold.co/600x400/FF0000/ffffff?text=NEET+Strategy",
                                    url: "https://www.youtube.com/@NextStepCounsel",
                                    duration: "15:20"
                                },
                                {
                                    id: 2,
                                    title: "Complete Counselling Process Explained",
                                    thumbnail: "https://placehold.co/600x400/FF0000/ffffff?text=Counselling+Process",
                                    url: "https://www.youtube.com/@NextStepCounsel",
                                    duration: "12:45"
                                },
                                {
                                    id: 3,
                                    title: "Best Medical Colleges in India",
                                    thumbnail: "https://placehold.co/600x400/FF0000/ffffff?text=Best+Colleges",
                                    url: "https://www.youtube.com/@NextStepCounsel",
                                    duration: "10:10"
                                }
                            ].map((video) => (
                                <div key={video.id} className="group relative bg-white rounded-2xl shadow-sm hover:shadow-xl transition-all border border-gray-100 overflow-hidden">
                                    <a href={video.url} target="_blank" rel="noreferrer" className="block relative h-48 overflow-hidden">
                                        <img src={video.thumbnail} alt={video.title} className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-500" />
                                        <div className="absolute inset-0 bg-black/20 group-hover:bg-black/40 transition-colors flex items-center justify-center">
                                            <div className="bg-red-600 text-white p-3 rounded-full transform group-hover:scale-110 transition-transform shadow-lg">
                                                <FaPlay size={16} className="ml-1" />
                                            </div>
                                        </div>
                                        <span className="absolute bottom-2 right-2 bg-black/70 text-white text-xs px-2 py-1 rounded font-medium">
                                            {video.duration}
                                        </span>
                                    </a>
                                    <div className="p-5">
                                        <h3 className="font-bold text-gray-900 group-hover:text-red-600 transition-colors line-clamp-2 mb-2">
                                            {video.title}
                                        </h3>
                                        <a href={video.url} target="_blank" rel="noreferrer" className="text-sm font-semibold text-gray-500 hover:text-red-600 transition-colors flex items-center gap-1">
                                            Watch on YouTube <FaArrowRight size={10} />
                                        </a>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="mt-16 text-center">
                        <p className="text-gray-500 mb-6">Want to stay updated?</p>
                        <a
                            href="https://t.me/+fVuyLUx2D_8wMTM1"
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-2 bg-[#229ED9] text-white px-8 py-3 rounded-full font-bold hover:bg-[#1d8dbf] transition shadow-lg hover:shadow-blue-200"
                        >
                            Join Telegram Channel
                        </a>
                    </div>
                </div>
            </section>
        </div>
    );
};

export default Blogs;
