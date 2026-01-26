import React, { useState } from 'react';
import { FaCheckCircle, FaWhatsapp, FaPhoneAlt, FaChevronDown, FaChevronUp } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';

const AyushCounselling = () => {
    const navigate = useNavigate();
    const [openFaqIndex, setOpenFaqIndex] = useState(null);

    const toggleFaq = (index) => {
        setOpenFaqIndex(openFaqIndex === index ? null : index);
    };

    const plans = [
        {
            title: "🌿 GOVT FOCUS PLAN",
            subtitle: "For students targeting only Government AYUSH Colleges (BAMS, BHMS, BUMS)",
            price: "6999",
            features: [
                "Dedicated Personal Counselor till final admission",
                "Personalized Govt AYUSH Preference List (BAMS, BHMS, BUMS)",
                "Verified Cutoff Data (Category-wise, Round-wise – Govt Colleges)",
                "Support for AACCC Counseling + 1 State AYUSH Counseling",
                "Seat Matrix, Bond, Hostel & Fee Info for Govt AYUSH Colleges",
                "Scholarship Guidance – Central & State Schemes",
                "Access to NextStep Counsel College Predictor Tool (AYUSH-integrated)",
                "Bond, Rural Service & Migration Rules (State-wise)",
                "Help with EWS, OBC, SC/ST Certificate & document uploading",
                "Round-wise Counseling Strategy – 1st, 2nd, Mop-up, Stray",
                "Refund & Exit Policy Guidance (AACCC/State)",
                "Access to Govt AYUSH Counseling eBook (PDF)",
                "College Reviews (Hospital OPD/IPD, Internship Scope, Hostel)",
                "Regular updates on Notifications, Cutoffs, Deadlines",
                "WhatsApp Support + Counselor Call Sessions",
                "Special AYUSH WhatsApp Group Access",
                "🎁 BONUS: ( MBBS + BDS ) Ideal Preference List for Backup"
            ],
            note: "Ideal for students focusing on Govt BAMS/BHMS/BUMS degrees.",
            color: "blue"
        },
        {
            title: "🌿 ALL-IN-ONE PREMIUM PLAN",
            subtitle: "Complete counseling support for Private, Govt & Deemed AYUSH Colleges",
            price: "11999",
            features: [
                "Dedicated Personal Counselor till final admission",
                "Personalized College Preference List (Govt + Pvt + Deemed AYUSH)",
                "Also includes MBBS + BDS Ideal Preference List for backup",
                "Verified Cutoff Data – AACCC, States & Deemed (Round-wise)",
                "Full support for All India Quota, State Counseling & Deemed Universities",
                "Access to NextStep Counsel College Predictor Tool",
                "Round-wise Counseling Strategy for all rounds – 1st, 2nd, Mop-up, Stray",
                "Detailed Seat Matrix, Hostel, Fee, Stipend & Bond data",
                "Help with Bond Rules, Domicile Requirements & Rural Service Obligations",
                "Document Guidance – Category, Domicile, Gap Year, Migration, NRI etc.",
                "Form Filling + Choice Filling Video Explanation Support",
                "Direct assistance in Scholarship & Education Loan Applications",
                "Guidance on Refund & Exit Policies (Govt + Pvt + Deemed)",
                "Access to NextStep Counsel Master Counseling eBook",
                "Full access to College Review Database (OPD, PG scope, Hostel, ROI)",
                "Special Premium WhatsApp Group for alerts, updates, cutoff trends",
                "Regular updates on Notifications, Deadlines, Circulars",
                "Post-Admission Checklist: Reporting, Hostel Join, University Registration"
            ],
            note: "Comprehensive support for all AYUSH courses across all college types.",
            color: "purple" // Using purple/pink gradient
        }
    ];

    const faqs = [
        {
            question: "What courses come under AYUSH Counselling?",
            answer: "AYUSH counselling covers admission to BAMS (Ayurveda), BHMS (Homeopathy), BUMS (Unani), BSMS (Siddha), and BNYS (Naturopathy & Yoga) courses."
        },
        {
            question: "Is NEET mandatory for AYUSH courses?",
            answer: "Yes, admission to all AYUSH undergraduate courses (BAMS/BHMS/BUMS) is strictly based on the NEET UG score."
        },
        {
            question: "Who conducts the counselling for AYUSH?",
            answer: "The AACCC (Ayush Admissions Central Counseling Committee) conducts counselling for 15% All India Quota seats. The remaining 85% state quota seats are managed by respective State Counselling Authorities."
        },
        {
            question: "Are there bonds in AYUSH colleges?",
            answer: "Yes, many government and some private AYUSH colleges have service bonds or discontinuation bonds. These rules vary by state and institution. Our plans cover detailed guidance on these bonds."
        },
        {
            question: "Can I apply for both MBBS/BDS and AYUSH Counselling?",
            answer: "Yes, these are separate counselling processes used to be conducted by MCC (for MBBS/BDS) and AACCC (for AYUSH). You can participate in both if you are eligible."
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
                    <h1 className="text-4xl md:text-5xl font-bold mb-4">AYUSH Counselling Guidance</h1>
                    <p className="text-xl text-gray-300 max-w-3xl mx-auto">
                        Expert guidance for BAMS, BHMS, BUMS Admissions. Get personalized support for AACCC & State Quota counselling.
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

export default AyushCounselling;
