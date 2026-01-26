import React, { useState } from 'react';
import { FaCheckCircle, FaWhatsapp, FaPhoneAlt, FaChevronDown, FaChevronUp } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';

const BVScCounselling = () => {
    const navigate = useNavigate();
    const [openFaqIndex, setOpenFaqIndex] = useState(null);

    const toggleFaq = (index) => {
        setOpenFaqIndex(openFaqIndex === index ? null : index);
    };

    const plans = [
        {
            title: "🐾 GOVT FOCUS PLAN",
            subtitle: "For students targeting only Government Veterinary Colleges through NEET",
            price: "6999",
            features: [
                "Dedicated Personal Counselor till final admission",
                "Personalized Govt Veterinary College Preference List (ICAR/AIPVT + State)",
                "Verified Cutoff Data – All India & State-wise (Category + Round-wise)",
                "Complete support for VCI/AIPVT Counseling + 1 State Counseling",
                "Detailed Seat Matrix, Hostel, Stipend & Fee Structure for Govt Vet Colleges",
                "Help with Bond Details, Service Conditions & Rural Posting Rules",
                "Assistance with Document Checklist – Domicile, Caste, Income, GAP, etc.",
                "Access to Form Filling + Choice Filling Video Tutorials",
                "Round-wise Strategy – 1st, 2nd, Mop-up, Stray (if applicable)",
                "Access to NextStep Counsel NEET College Predictor Tool",
                "Scholarship Guidance – ICAR, National/State Vet Schemes",
                "Access to Govt Veterinary Counseling eBook (PDF)",
                "College Reviews (Hospital OPD, Animal Load, Internship Scope)",
                "Regular updates on Notifications, Circulars & Deadlines",
                "WhatsApp Support + Live Counselor Calls",
                "Special Veterinary Counseling WhatsApp Group Access",
                "🎁 Bonus: MBBS, BDS, AYUSH Ideal Preference List for backup"
            ],
            note: "Ideal for students focused solely on Government Veterinary seats.",
            color: "blue"
        },
        {
            title: "🐾 ALL-IN-ONE PREMIUM PLAN",
            subtitle: "Complete counseling support for Private, Deemed & Semi-Govt Veterinary Colleges",
            price: "11999",
            features: [
                "Dedicated Personal Counselor till final admission",
                "Personalized Preference List of Govt/Private/Deemed Vet Colleges",
                "Verified Cutoff Data – State/Private rounds (if applicable)",
                "Full support for State Counseling + Direct College Application Routes",
                "Guidance for Trust/Minority/Management Quota Seats",
                "Access to NextStep Counsel College Predictor Tool",
                "Complete assistance with Seat Matrix, Hostel, Fee & Stipend Structures",
                "Bond Rules, Management Fee Policies & Hostel Info",
                "Guidance on Refund Rules, Admission Withdrawal, Fee Adjustment",
                "Document Support – GAP, NRI quota, Migration, Income, Domicile, etc.",
                "Form Filling + Choice Filling Video Explanation Support",
                "Manual Assistance in Form Filling & Choice Entry by Team NextStep Counsel",
                "Help in verifying UGC-recognized Veterinary Colleges",
                "Scholarship & Education Loan Support for Private BVSc",
                "Access to NextStep Counsel Veterinary Counseling eBook (Govt + Pvt Combined)",
                "Full College Review Access – Patient Load, Clinical Exposure, PG Options",
                "Special Premium Vet Counseling WhatsApp Group",
                "🎁 BONUS: MBBS + AYUSH + BAMS Preference Lists (backup)"
            ],
            note: "Comprehensive support for all Veterinary colleges including Private & Deemed.",
            color: "purple" // Using purple/pink gradient
        }
    ];

    const faqs = [
        {
            question: "What is BVSc & AH?",
            answer: "BVSc & AH stands for Bachelor of Veterinary Science and Animal Husbandry. It is an undergraduate course for becoming a veterinarian (animal doctor)."
        },
        {
            question: "Is NEET required for BVSc Admission?",
            answer: "Yes, admission to BVSc & AH courses under the 15% All India Quota (conducted by VCI) is based on NEET UG scores. Most states also use NEET scores for their state quota veterinary admissions."
        },
        {
            question: "Who conducts All India Veterinary Counselling?",
            answer: "The Veterinary Council of India (VCI) conducts the counselling for 15% All India Quota seats in recognized veterinary colleges across India."
        },
        {
            question: "What is the scope after BVSc?",
            answer: "Graduates can work as Veterinary Doctors in Govt/Private hospitals, join the Army (RVC), work in pharmaceutical companies, research institutes, zoos, or open their own private practice."
        },
        {
            question: "Are there government jobs for BVSc graduates?",
            answer: "Yes, there are regular government vacancies for Veterinary Open Surgeons (VO) in state animal husbandry departments, as well as opportunities in banks (Agricultural Officers) and defense services."
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
                    <h1 className="text-4xl md:text-5xl font-bold mb-4">BVSc & AH Veterinary Counselling Guidance</h1>
                    <p className="text-xl text-gray-300 max-w-3xl mx-auto">
                        Expert guidance for Veterinary Admissions. Secure your seat in top Government & Private Vet Colleges.
                    </p>
                </div>
            </section>

            {/* Plans Section */}
            <section className="py-16 bg-gray-50">
                <div className="container mx-auto px-4">
                    <div className="text-center mb-12">
                        <h2 className="text-3xl font-bold text-gray-900">Choose Your Plan</h2>
                        <div className="w-24 h-1 bg-gradient-to-r from-[#E15583] to-[#8361D0] mx-auto mt-4 rounded-full"></div>
                    </div>

                    <div className="grid lg:grid-cols-2 gap-8 max-w-7xl mx-auto">
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
                                        <div className="text-right">
                                            <span className="block text-sm opacity-80">Starting at</span>
                                            <span className="text-3xl font-bold">₹ {parseInt(plan.price).toLocaleString()}</span>
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
                                        Buy Now
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
                                    className="w-full flex justify-between items-center p-5 bg-gray-50 hover:bg-white text-left focus:outline-none transition-colors duration-300"
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
                        <a href="https://wa.me/917014264008" target="_blank" rel="noreferrer" className="flex items-center justify-center gap-2 bg-green-500 hover:bg-green-600 text-white px-8 py-3 rounded-full font-bold transition">
                            <FaWhatsapp size={20} /> Chat on WhatsApp
                        </a>
                        <a href="tel:7014264008" className="flex items-center justify-center gap-2 bg-gray-900 hover:bg-gray-800 text-white px-8 py-3 rounded-full font-bold transition">
                            <FaPhoneAlt size={18} /> Call +91 7014264008
                        </a>
                    </div>
                </div>
            </section>
        </div>
    );
};

export default BVScCounselling;
