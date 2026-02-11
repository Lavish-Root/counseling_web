import React, { useState } from 'react';
import { FaCheckCircle, FaWhatsapp, FaPhoneAlt, FaChevronDown, FaChevronUp } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';

const BDSCounselling = () => {
    const navigate = useNavigate();
    const [openFaqIndex, setOpenFaqIndex] = useState(null);

    const toggleFaq = (index) => {
        setOpenFaqIndex(openFaqIndex === index ? null : index);
    };

    const plans = [
        {
            title: "🦷 GOVT FOCUS PLAN",
            subtitle: "For students targeting only Government Dental Colleges (BDS)",
            price: "5999",
            features: [
                "Dedicated Personal Counselor till final admission",
                "Personalized Govt Dental Preference List (Central, State Govt BDS)",
                "Verified Cutoff Data (Category-wise, Round-wise – BDS only)",
                "Complete support for MCC + 1 State Dental Counseling",
                "Govt Dental Seat Matrix, Bond, Fees & Stipend info",
                "Scholarship Guidance – Central & State schemes",
                "Access to NextStep Counsel College Predictor Tool",
                "State-specific Bond & Migration Rules explained",
                "Help with EWS, OBC, SC/ST Certificate & document uploading",
                "Round-wise Counseling Strategy – 1st, 2nd, Mop-up, Stray",
                "Regular updates on Notifications & Circulars",
                "College Reviews – OPD load, internships, hostel life, PG options",
                "Access to Govt Dental Counseling eBook (PDF)",
                "WhatsApp Support + Counselor Call Sessions",
                "Form Filling + Choice Filling Video Explanation Support",
                "Guidance on Refund & Exit Policy",
                "Access to Special WhatsApp Group",
                "🎁 Also get ideal preference list for Govt MBBS and BAMS (backup)"
            ],
            note: "Ideal for students/parents focused solely on Govt Dental seats.",
            color: "blue"
        },
        {
            title: "🦷 ALL-IN-ONE PREMIUM PLAN",
            subtitle: "Complete counseling support for Govt + Private + Deemed Dental Colleges (BDS)",
            price: "9999",
            features: [
                "Dedicated Personal Counselor till final admission",
                "Personalized College Preference List (Govt + Pvt + Deemed Dental)",
                "Also includes MBBS + BAMS Ideal Preference List for backup",
                "Verified Cutoff Data – MCC, States & Deemed (Round-wise)",
                "Full support for All India Quota, State Counseling & Deemed Universities",
                "Access to NextStep Counsel College Predictor Tool",
                "Round-wise Counseling Strategy for all rounds – 1st, 2nd, Mop-up, Stray",
                "Detailed Seat Matrix, Hostel, Fee, Stipend & Bond data",
                "Help with Bond Rules, Domicile Requirements & Rural Service Obligations",
                "Document Guidance – Category, Domicile, Gap Year, Migration, NRI etc.",
                "Form Filling + Choice Filling Video Explanation Support",
                "Direct assistance in Scholarship & Education Loan Applications",
                "Guidance on Refund & Exit Policies (Govt + Pvt + Deemed)",
                "Access to NextStep Counsel Master Counseling eBook (Govt + Pvt + Deemed)",
                "Full access to College Review Database (OPD, PG scope, Hostel, ROI)",
                "Special Premium WhatsApp Group for alerts, updates, cutoff trends",
                "Regular updates on Notifications, Deadlines, Circulars",
                "Post-Admission Checklist: Reporting, Hostel Join, Docs"
            ],
            note: "Comprehensive support for all types of Dental colleges + MBBS Backup strategy.",
            color: "purple" // Using purple/pink gradient
        }
    ];

    const faqs = [
        {
            question: "What is BDS counselling?",
            answer: "BDS counselling is the process for admission to Bachelor of Dental Surgery courses in India. It is conducted by the MCC for All India Quota seats and by respective State Authorities for state quota seats, based on NEET UG scores."
        },
        {
            question: "Do I need to register separately for BDS Counselling?",
            answer: "Yes, usually you register for MCC counseling for 15% AIQ seats (which includes BDS). For state quota seats (85%), you must register with your respective state's counseling authority."
        },
        {
            question: "What is the scope of BDS?",
            answer: "BDS graduates can work as dentists in government or private hospitals, open their own clinics, pursue MDS (Masters) for specialization, or explore opportunities in research, public health, and overseas practice."
        },
        {
            question: "Is there a specific cutoff for BDS?",
            answer: "Yes, admissions are based on NEET ranks. Cutoffs for BDS are generally slightly lower than MBBS but vary significantly between Government and Private/Deemed colleges."
        },
        {
            question: "Can I participate in both MBBS and BDS counselling?",
            answer: "Yes, the MCC counselling form allows you to select choices for both MBBS and BDS courses. You can list them in your preference order during choice filling."
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
                    <h1 className="text-4xl md:text-5xl font-bold mb-4">BDS Dental Counselling Guidance</h1>
                    <p className="text-xl text-gray-300 max-w-3xl mx-auto">
                        Secure your seat in top Dental Colleges. Expert guidance for All India & State Quota BDS admissions.
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

export default BDSCounselling;
