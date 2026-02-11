import React, { useState } from 'react';
import { FaCheckCircle, FaWhatsapp, FaPhoneAlt, FaChevronDown, FaChevronUp } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';

const CentralGovtCounselling = () => {
    const navigate = useNavigate();
    const [openFaqIndex, setOpenFaqIndex] = useState(null);

    const toggleFaq = (index) => {
        setOpenFaqIndex(openFaqIndex === index ? null : index);
    };

    const plans = [
        {
            title: "Starter Guidance Plan",
            subtitle: "Best for basic clarity & safe start",
            price: "999",
            features: [
                "Exam-wise Counselling (UPSC / SSC / Railway / Banking / Defence)",
                "Eligibility & Exam Pattern Explanation",
                "Syllabus + Preparation Direction",
                "Previous Year Cut-off & Trend Overview",
                "Basic Form-Filling Guidance",
                "Official Notice Updates (WhatsApp)",
                "Common Mistakes to Avoid"
            ],
            note: "Ideal for beginners & first-time aspirants",
            color: "blue"
        },
        {
            title: "Smart Strategy Plan",
            subtitle: "Rank + career focused planning",
            price: "1999",
            features: [
                "Everything in ₹999 Plan",
                "Rank / Score Based Guidance",
                "Post Preference Strategy (SSC / Banking / RRB)",
                "Vacancy & Posting Location Insight",
                "Document Verification Checklist",
                "Job Profile, Salary & Promotion Explain",
                "One-on-One Mentor Call (Limited)",
                "WhatsApp Support till selection stage"
            ],
            note: "Best for serious aspirants aiming safe selection",
            color: "blue"
        },
        {
            title: "Premium Success Plan",
            subtitle: "Complete hand-holding till final joining",
            price: "4999",
            features: [
                "Everything in ₹1999 Plan",
                "Dedicated Personal Mentor Assigned",
                "UPSC: Optional + Interview Guidance",
                "SSC/Banking: Final Post Allotment Strategy",
                "Defence: Written + SSB + Medical Guidance",
                "Preference Filling (Live Support)",
                "Error-Free Form & Choice Filling",
                "Unlimited WhatsApp + Call Support",
                "Support till Final Selection / Joining"
            ],
            note: "Perfect for rank-holders & high-stakes aspirants",
            color: "purple"
        }
    ];

    const faqs = [
        {
            question: "What is Central Government Exam counselling?",
            answer: "Central Government Exam counselling is a structured guidance process that helps candidates choose the right government exams, understand eligibility, selection process, and plan their preparation and career path."
        },
        {
            question: "Is any common exam required for Central Government jobs?",
            answer: "No single exam applies to all posts. Different exams like SSC, UPSC, Banking, Railways, and Defence have their own eligibility criteria and selection processes."
        },
        {
            question: "Who conducts Central Government recruitment exams?",
            answer: "Central Government exams are conducted by bodies such as UPSC, SSC, IBPS, RRB, and respective ministries or departments."
        },
        {
            question: "What is the career scope in Central Government jobs?",
            answer: "Central Government jobs offer stable careers with good salary, job security, promotions, pensions, and opportunities across administrative, technical, defence, and financial sectors."
        },
        {
            question: "Are government jobs available across different departments?",
            answer: "Yes. Central Government jobs are available in multiple departments including administration, defence, railways, banking, taxation, research, and public sector undertakings."
        }
    ];

    const handleBuyNow = (plan) => {
        navigate('/cart', { state: { plan } });
    };

    return (
        <div className="font-sans">
            {/* Hero Section */}
            <section className="relative bg-gradient-to-r from-[#0f172a] to-[#1e293b] text-white py-20 lg:py-28">
                <div className="absolute inset-0 bg-[url('/assets/bg-pattern.webp')] opacity-5 mix-blend-overlay"></div>
                <div className="container mx-auto px-4 relative z-10 text-center">
                    <h1 className="text-4xl md:text-5xl font-bold mb-6">Central Govt. Exam Counselling & Guidance</h1>
                    <p className="text-xl text-gray-300 max-w-3xl mx-auto mb-8">
                        Expert guidance for UPSC, SSC, Railway, Banking & Defence Exams.
                        Right strategy, correct form filling & career-focused counselling for top Government Jobs.
                    </p>

                </div>
            </section>

            {/* Intro/Services Section */}
            <section className="py-16 bg-white">
                <div className="container mx-auto px-4 max-w-5xl">
                    <div className="grid md:grid-cols-2 gap-12 items-center">
                        <div>
                            <h2 className="text-3xl font-bold text-gray-900 mb-6">Your Path to a Government Career</h2>
                            <p className="text-gray-600 mb-6 leading-relaxed">
                                Crack the toughest exams with the right strategy. Our experts help you understand the exam pattern, syllabus, and selection process in depth.
                            </p>
                            <ul className="space-y-3">
                                {[
                                    "Exam Selection & Eligibility Checks",
                                    "Personalized Study Roadmap",
                                    "Form Filling & Preference Selection",
                                    "Doubt Clearing Sessions",
                                    "Interview Guidance",
                                    "Final Selection Support"
                                ].map((item, i) => (
                                    <li key={i} className="flex items-center gap-3 text-gray-700 font-medium">
                                        <FaCheckCircle className="text-green-500 flex-shrink-0" /> {item}
                                    </li>
                                ))}
                            </ul>
                        </div>
                        <div className="bg-blue-50 p-8 rounded-2xl border border-blue-100">
                            <h3 className="text-xl font-bold mb-4 text-blue-800">Clear Your Doubts</h3>
                            <p className="text-gray-600 mb-4">
                                Confused about which post to prefer? Don't know the service conditions? Talk to our experts today.
                            </p>
                            <div className="flex items-center gap-4 p-4 bg-white rounded-xl shadow-sm">
                                <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center text-green-600 font-bold text-xl">
                                    <FaWhatsapp />
                                </div>
                                <div>
                                    <p className="text-xs text-gray-500 uppercase font-bold">Get Guidance Now</p>
                                    <p className="font-bold text-lg text-gray-900">95889 28940</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* Plans Section */}
            <section className="py-16 bg-gray-50">
                <div className="container mx-auto px-4">
                    <div className="text-center mb-12">
                        <h2 className="text-3xl font-bold text-gray-900">Premium Counselling Plans</h2>
                        <div className="w-24 h-1 bg-gradient-to-r from-[#E15583] to-[#8361D0] mx-auto mt-4 rounded-full"></div>
                        <p className="mt-4 text-gray-500">Structured guidance for your dream job.</p>
                    </div>

                    <div className="grid lg:grid-cols-3 gap-8 max-w-7xl mx-auto">
                        {plans.map((plan, index) => (
                            <div
                                key={index}
                                className={`bg-white rounded-3xl shadow-lg border overflow-hidden hover:shadow-2xl transition-shadow duration-300 flex flex-col ${plan.color === 'purple' ? 'border-primary-purple/20' : 'border-blue-100'}`}
                            >
                                <div className={`p-8 ${plan.color === 'purple' ? 'bg-gradient-to-r from-[#E15583] to-[#8361D0] text-white' : 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white'}`}>
                                    <div className="flex justify-between items-start">
                                        <div>
                                            <h3 className="text-2xl font-bold mb-2">{plan.title}</h3>
                                            <p className="opacity-90 font-medium text-sm leading-relaxed max-w-md">{plan.subtitle}</p>
                                        </div>
                                    </div>
                                </div>

                                <div className="p-8 flex-grow">
                                    <ul className="space-y-4">
                                        {plan.features.map((feature, i) => (
                                            <li key={i} className="flex items-start gap-3">
                                                <FaCheckCircle className={`mt-1 flex-shrink-0 ${plan.color === 'purple' ? 'text-primary-purple' : 'text-blue-500'}`} />
                                                <span className="text-gray-700 leading-relaxed">{feature}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>

                                <div className="p-8 bg-gray-50 border-t border-gray-100 mt-auto">
                                    <div className="flex bg-yellow-50 border border-yellow-200 p-4 rounded-xl mb-6">
                                        <p className="text-sm text-yellow-800 italic">
                                            <strong>Note:</strong> {plan.note}
                                        </p>
                                    </div>
                                    <button
                                        onClick={() => handleBuyNow(plan)}
                                        className={`w-full py-4 rounded-xl font-bold text-lg text-white shadow-lg transition transform hover:-translate-y-1 active:scale-95 cursor-pointer ${plan.color === 'purple' ? 'bg-gradient-to-r from-[#E15583] to-[#8361D0] hover:shadow-primary-purple/30' : 'bg-gradient-to-r from-blue-600 to-cyan-600 hover:shadow-blue-500/30'}`}
                                    >
                                        Book Now +91 95889 28940
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* FAQ Section */}
            <section className="py-16 bg-white border-t border-gray-100">
                <div className="container mx-auto px-4 max-w-4xl">
                    <div className="text-center mb-12">
                        <h2 className="text-3xl font-bold text-gray-900">Frequently Asked Questions</h2>
                        <div className="w-20 h-1 bg-gradient-to-r from-[#E15583] to-[#8361D0] mx-auto mt-4 rounded-full"></div>
                    </div>

                    <div className="space-y-4">
                        {faqs.map((faq, index) => (
                            <div
                                key={index}
                                className="border border-gray-200 rounded-xl overflow-hidden hover:border-primary-purple/50 transition duration-300"
                            >
                                <button
                                    className="w-full flex justify-between items-center p-5 bg-gray-50 hover:bg-white text-left focus:outline-none transition-colors duration-300 cursor-pointer"
                                    onClick={() => toggleFaq(index)}
                                >
                                    <span className="font-semibold text-gray-900 text-lg">{faq.question}</span>
                                    {openFaqIndex === index ? (
                                        <FaChevronUp className="text-primary-purple" />
                                    ) : (
                                        <FaChevronDown className="text-gray-400" />
                                    )}
                                </button>
                                <div
                                    className={`overflow-hidden transition-all duration-300 ease-in-out ${openFaqIndex === index ? 'max-h-96 opacity-100' : 'max-h-0 opacity-0'}`}
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

            {/* Contact CTA Section */}
            <section className="py-16 bg-gray-50 border-t border-gray-100">
                <div className="container mx-auto px-4 text-center">
                    <h2 className="text-2xl font-bold mb-8">Need help with your preparation?</h2>
                    <div className="flex flex-col sm:flex-row justify-center gap-6">
                        <a href="https://wa.me/919588928940" target="_blank" rel="noreferrer" className="flex items-center justify-center gap-2 bg-green-500 hover:bg-green-600 text-white px-8 py-3 rounded-full font-bold transition">
                            <FaWhatsapp size={20} /> Chat on WhatsApp
                        </a>
                        <a href="tel:9588928940" className="flex items-center justify-center gap-2 bg-gray-900 hover:bg-gray-800 text-white px-8 py-3 rounded-full font-bold transition">
                            <FaPhoneAlt size={18} /> Call +91 9588928940
                        </a>
                    </div>
                </div>
            </section>
        </div>
    );
};

export default CentralGovtCounselling;
