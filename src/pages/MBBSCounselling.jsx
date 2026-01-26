import React, { useState } from 'react';
import { FaCheckCircle, FaWhatsapp, FaPhoneAlt, FaChevronDown, FaChevronUp } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';

const MBBSCounselling = () => {
    const navigate = useNavigate();
    const [openFaqIndex, setOpenFaqIndex] = useState(null);

    const toggleFaq = (index) => {
        setOpenFaqIndex(openFaqIndex === index ? null : index);
    };

    const plans = [
        {
            title: "🏥 GOVT FOCUS PLAN (PRIME)",
            subtitle: "For students targeting only AIIMS, JIPMER & Government MBBS Colleges",
            price: "11999",
            features: [
                "Dedicated Personal Counselor till final admission",
                "Personalized Govt-only Preference List (AIIMS, GMCs, State quota)",
                "Verified Cutoff Data (Category + Round-wise)",
                "Complete support for MCC + 1 State Counseling",
                "Seat Matrix, Bond, Fees & Stipend info",
                "Scholarship Guidance – Central + State schemes",
                "Access to NextStep Counsel College Predictor Tool",
                "State-specific Bond/Migration rules explained",
                "Support for EWS, OBC, SC/ST Certificate Documents",
                "Round-wise Strategy: 1st, 2nd, Mop-up, Stray",
                "Regular updates on Circulars & Notifications",
                "College Reviews: OPD strength, PG seats, hostel, internships",
                "Access to Govt College Counseling eBook (PDF)",
                "WhatsApp Support + Call Sessions with Counselor",
                "(Form Filling + Choice Filling) Video Explanation Support",
                "Refund & Exit Policy Guidance",
                "Special Users WhatsApp Group"
            ],
            note: "Ideal for students/parents who want full support in every step for Govt colleges only.",
            color: "blue"
        },
        {
            title: "🏥 ALL-IN-ONE PREMIUM PLAN",
            subtitle: "Complete counseling support for Govt + Private + Deemed + Management MBBS Colleges",
            price: "19999",
            features: [
                "Dedicated Personal Counselor till final admission",
                "Personalized College Preference List (Govt + Pvt + Deemed)",
                "Verified Cutoff Data – MCC + All States + Deemed (Round-wise)",
                "Full support for All India (AIQ), State Quotas & Deemed Universities",
                "Access to NextStep Counsel College Predictor Tool",
                "Round-wise Counseling Strategy for each type",
                "Detailed Seat Matrix, Hostel, Stipend & Fee Structures",
                "Guidance for Bond Rules, Rural Service, Domicile Conditions",
                "Help with Documents – Category, Domicile, Gap, Migration, NRI docs",
                "Form Filling + Choice Filling Video Explanation Support",
                "Direct assistance in Scholarship + Education Loan Application",
                "Refund & Exit Policy Guidance (Govt, Pvt & Deemed)",
                "Access to NextStep Counsel’s Master Counseling eBook",
                "Full database of College Reviews – patient load, ROI etc.",
                "Special Premium WhatsApp Group Access",
                "Regular updates on Notifications, Deadlines & Circulars",
                "Post-Admission Checklist: Reporting, Hostel, Reg, Doc Check"
            ],
            note: "Choose this if you are considering Private/Deemed options along with Government.",
            color: "purple" // Using purple/pink gradient
        }
    ];

    const faqs = [
        {
            question: "What is MBBS counselling?",
            answer: "MBBS counselling is the official procedure for gaining admission to medical colleges after the NEET exam. Based on your NEET score or rank, you are assigned a college through either the All India Quota (AIQ) or State Quota counselling."
        },
        {
            question: "Who conducts MBBS counselling in India?",
            answer: "The Medical Counselling Committee (MCC) conducts the All India Quota (AIQ) for 15% of government seats and 100% of seats in deemed/central universities. State counselling authorities conduct counselling for the remaining 85% state quota seats."
        },
        {
            question: "What is the NRI Quota in MBBS?",
            answer: "The NRI Quota allows Indian-origin students living abroad to apply for reserved seats in specific medical colleges. It typically requires higher fees and specific documentation proof of NRI status."
        },
        {
            question: "What is the Mop-Up Round?",
            answer: "The Mop-Up Round is a special round conducted to fill vacant seats after Round 1 and Round 2 of counselling. It acts as a second chance for students who haven't secured a seat in the initial rounds."
        },
        {
            question: "What is the Stray Round?",
            answer: "The Stray Round is the final chance to get any remaining MBBS seats in private or deemed colleges, usually conducted at the institute level to fill any last-minute vacancies."
        },
        {
            question: "What documents are typically required?",
            answer: "Key documents include: NEET Admit Card & Scorecard, 10th and 12th Marksheets, Domicile Certificate, Caste/Category Certificate (if applicable), ID Proof (Aadhaar/PAN), and passport-sized photographs."
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
                    <h1 className="text-4xl md:text-5xl font-bold mb-4">MBBS Counselling Guidance</h1>
                    <p className="text-xl text-gray-300 max-w-3xl mx-auto">
                        Expert guidance for AIQ & State Quota MBBS admissions. Get personalized support throughout your medical counselling journey.
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
                        <a href="https://wa.me/7203086849" target="_blank" rel="noreferrer" className="flex items-center justify-center gap-2 bg-green-500 hover:bg-green-600 text-white px-8 py-3 rounded-full font-bold transition">
                            <FaWhatsapp size={20} /> Chat on WhatsApp
                        </a>
                        <a href="tel:7203086849" className="flex items-center justify-center gap-2 bg-gray-900 hover:bg-gray-800 text-white px-8 py-3 rounded-full font-bold transition">
                            <FaPhoneAlt size={18} /> Call +91 72030 86849
                        </a>
                    </div>
                </div>
            </section>
        </div>
    );
};

export default MBBSCounselling;
