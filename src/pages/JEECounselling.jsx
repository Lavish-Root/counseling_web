import React, { useState } from 'react';
import { FaCheckCircle, FaWhatsapp, FaPhoneAlt, FaChevronDown, FaChevronUp } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';

const JEECounselling = () => {
    const navigate = useNavigate();
    const [openFaqIndex, setOpenFaqIndex] = useState(null);

    const toggleFaq = (index) => {
        setOpenFaqIndex(openFaqIndex === index ? null : index);
    };

    const plans = [
        {
            title: "Next Step Navigator – JEE Counselling Plan",
            subtitle: "Expert Guidance & Smart Tools",
            price: "4999",
            features: [
                "Expert JEE Counselling: Covers JEE Main & JEE Advanced for JoSAA & State Counselling.",
                "JEE Mentors (1-to-1): Personal counsellor for rank-based guidance & decision making.",
                "Complete JoSAA Support: Round-wise guidance for IITs, NITs, IIITs & GFTIs.",
                "Smart Choice-Filling: Custom college & branch list based on rank, category & preference.",
                "College & Branch Data: Quick access to cut-offs, fees, placements & seat matrix.",
                "Step-by-Step Form Filling: Registration → Choice Filling → Locking → Reporting (error-free).",
                "Upgrade Strategy Support: Freeze / Float / Slide decision with minimum risk planning.",
                "WhatsApp & Call Support: Ongoing support till final round completion.",
                "Rule & Update Alerts: Latest JoSAA & State counselling rule updates explained clearly.",
                "Backup & Safety Planning: Avoid seat loss with safe college backup strategy."
            ],
            note: "Balanced support for most aspirants.",
            color: "teal"
        },
        {
            title: "Next Step Pro – JEE Counselling Plan",
            subtitle: "Comprehensive Premium Support",
            price: "9999",
            features: [
                "Advanced JEE Counselling: JEE Main & Advanced for JoSAA + All State Counselling.",
                "Senior Expert Counsellor (1-to-1): Branch vs College deep analysis with future scope.",
                "Unlimited Choice-Filling Revisions: Rank change, round change — no limit edits.",
                "Branch Priority Strategy: CS vs Core vs Circuital — career-based guidance.",
                "Round-wise Upgrade Planning: R1 to Last Round seat upgrade roadmap.",
                "Live Screen-Share Support: Choice filling & locking real-time assistance.",
                "Cut-off + Placement Insights: Past + latest data with placement trend explanation.",
                "Parent Counselling Support: Parents ko bhi clear & confident decision making.",
                "WhatsApp + Priority Call Support: Fast response till final admission."
            ],
            note: "Ultimate guidance for top-tier results.",
            color: "purple"
        }
    ];

    const faqs = [
        {
            question: "What is JEE Counselling?",
            answer: "JEE Counselling is the centralized seat allocation process through which students get admission into IITs, NITs, IIITs, and other engineering colleges based on their JEE Main/Advanced ranks."
        },
        {
            question: "Do I need to register separately for JEE Counselling?",
            answer: "Yes. Candidates must register separately for counselling through the official portals like JoSAA (for IITs/NITs/IIITs) or State Counselling Authorities."
        },
        {
            question: "What is the scope after JEE?",
            answer: "JEE opens doors to top engineering institutes in India, offering strong career opportunities in engineering, technology, research, public sector jobs, and higher studies in India or abroad."
        },
        {
            question: "Is there a specific cutoff for JEE Counselling?",
            answer: "Yes. Cutoffs vary every year based on exam difficulty, number of candidates, category, institute, branch preference, and seat availability."
        },
        {
            question: "Can I participate in both Central and State JEE Counselling?",
            answer: "Yes. Eligible candidates can participate in both JoSAA (Central Counselling) and respective State Counselling processes simultaneously, as per their rank and eligibility."
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
                    <h1 className="text-4xl md:text-5xl font-bold mb-6">JEE Counselling & College Selection Guidance</h1>
                    <p className="text-xl text-gray-300 max-w-3xl mx-auto mb-8">
                        Get expert support for JoSAA & State Counselling. Choose the best IIT, NIT, IIIT & GFTI based on your rank.
                    </p>
                    <div className="flex flex-wrap justify-center gap-4 text-sm font-medium text-blue-200">
                        <span className="bg-blue-900/50 px-3 py-1 rounded-full border border-blue-700">JoSAA Counselling</span>
                        <span className="bg-blue-900/50 px-3 py-1 rounded-full border border-blue-700">CSAB Special Rounds</span>
                        <span className="bg-blue-900/50 px-3 py-1 rounded-full border border-blue-700">College Prediction</span>
                    </div>
                </div>
            </section>

            {/* Intro/Services Section */}
            <section className="py-16 bg-white">
                <div className="container mx-auto px-4 max-w-5xl">
                    <div className="grid md:grid-cols-2 gap-12 items-center">
                        <div>
                            <h2 className="text-3xl font-bold text-gray-900 mb-6">Complete Engineering Counselling Support</h2>
                            <p className="text-gray-600 mb-6 leading-relaxed">
                                Navigate the complex JoSAA and CSAB counselling process with ease. We help you optimize your choices to get the best possible college for your rank.
                            </p>
                            <ul className="space-y-3">
                                {[
                                    "JoSAA & CSAB Counselling Guidance",
                                    "College & Branch Preference Strategy",
                                    "Round-wise Seat Analysis",
                                    "Choice Filling Assistance",
                                    "Document Verification Help",
                                    "Admission Confirmation Support"
                                ].map((item, i) => (
                                    <li key={i} className="flex items-center gap-3 text-gray-700 font-medium">
                                        <FaCheckCircle className="text-green-500 flex-shrink-0" /> {item}
                                    </li>
                                ))}
                            </ul>
                        </div>
                        <div className="bg-blue-50 p-8 rounded-2xl border border-blue-100">
                            <h3 className="text-xl font-bold mb-4 text-blue-800">Why Expert Guidance?</h3>
                            <p className="text-gray-600 mb-4">
                                A wrong preference order can cost you a seat in a better college or branch. Let experts handle your choice filling.
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
                        <h2 className="text-3xl font-bold text-gray-900">Premium Paid Counselling Support</h2>
                        <div className="w-24 h-1 bg-gradient-to-r from-[#E15583] to-[#8361D0] mx-auto mt-4 rounded-full"></div>
                        <p className="mt-4 text-gray-500">Want guaranteed expert support for your Engineering admission?</p>
                    </div>

                    <div className="grid lg:grid-cols-2 gap-8 max-w-5xl mx-auto">
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
                    <h2 className="text-2xl font-bold mb-8">Need help choosing a plan?</h2>
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

export default JEECounselling;
