import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FaFacebook, FaYoutube, FaWhatsapp, FaEnvelope, FaTelegramPlane, FaInstagram, FaArrowUp } from 'react-icons/fa';

import logo from '../assets/nextstep_logo.jpg';

const Footer = () => {
    const [showScrollToTop, setShowScrollToTop] = useState(false);

    useEffect(() => {
        const handleScroll = () => {
            // Check if user has scrolled down 10% of the page
            const scrollTotal = document.documentElement.scrollHeight - window.innerHeight;
            if (window.scrollY > scrollTotal * 0.1) {
                setShowScrollToTop(true);
            } else {
                setShowScrollToTop(false);
            }
        };

        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    const scrollToTop = () => {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    };

    return (
        <footer className="bg-dark-bg text-white pt-16 pb-8 border-t border-gray-800">
            <div className="container mx-auto px-4 grid md:grid-cols-4 gap-8 mb-12">
                {/* Brand & About */}
                <div>
                    <Link to="/" className="mb-4 block">
                        <img src={logo} alt="NextStep Counsel" className="h-12 w-auto rounded-full" />
                    </Link>
                    <p className="text-gray-400 text-sm mb-6">
                        India’s Trusted Counselling & Career Guidance Platform. We guide students from Registration to Final Admission with complete transparency and expert support.
                    </p>
                    <div className="flex space-x-4">
                        <a href="https://whatsapp.com/channel/0029Vb6rlzt59PwKkP1P9R3A" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition" title="WhatsApp Channel"><FaWhatsapp /></a>
                        <a href="https://www.youtube.com/@NextStepCounsel" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition" title="YouTube"><FaYoutube /></a>
                        <a href="https://t.me/+fVuyLUx2D_8wMTM1" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition" title="Telegram"><FaTelegramPlane /></a>
                        <a href="https://www.instagram.com/nextstepcounsel01/" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition" title="Instagram"><FaInstagram /></a>
                        <a href="https://www.facebook.com/share/1KMANqGWhF/" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition" title="Facebook"><FaFacebook /></a>
                    </div>
                </div>

                {/* Links and Services Group */}
                <div className="grid grid-cols-2 gap-4 md:col-span-2 md:gap-8">
                    {/* Quick Links */}
                    <div>
                        <h4 className="font-bold text-lg mb-6">Quick Links</h4>
                        <ul className="space-y-3 text-sm text-gray-400">
                            <li><a href="https://mcc.nic.in/" target="_blank" rel="noreferrer" className="hover:text-primary-pink transition">MCC Counselling</a></li>
                            <li><a href="https://www.upsc.gov.in/" target="_blank" rel="noreferrer" className="hover:text-primary-pink transition">UPSC Official</a></li>
                            <li><a href="https://ssc.nic.in/" target="_blank" rel="noreferrer" className="hover:text-primary-pink transition">SSC Official</a></li>
                            <li><Link to="/terms" className="hover:text-primary-pink transition">Terms & Conditions</Link></li>
                            <li><Link to="/privacy" className="hover:text-primary-pink transition">Privacy Policy</Link></li>
                            <li><Link to="/refund" className="hover:text-primary-pink transition">Refund Policy</Link></li>
                        </ul>
                    </div>

                    {/* Services */}
                    <div>
                        <h4 className="font-bold text-lg mb-6">Our Services</h4>
                        <ul className="space-y-3 text-sm text-gray-400">
                            <li><Link to="/counselling/mbbs" className="hover:text-primary-pink transition">NEET UG Counselling</Link></li>
                            <li><Link to="/courses" className="hover:text-primary-pink transition">Competitive Exams</Link></li>
                            <li><Link to="/counselling" className="hover:text-primary-pink transition">Paid Counselling</Link></li>
                            <li><Link to="/ebooks" className="hover:text-primary-pink transition">Updates & Resources</Link></li>
                        </ul>
                    </div>
                </div>

                {/* Contact */}
                <div>
                    <h4 className="font-bold text-lg mb-6">Get In Touch</h4>
                    <ul className="space-y-4 text-sm text-gray-400">
                        <li className="flex items-center gap-3">
                            <FaWhatsapp className="text-primary-pink" />
                            <a href="https://wa.me/919588928940" target="_blank" rel="noreferrer">95889 28940</a>
                        </li>
                        <li className="flex items-center gap-3">
                            <FaEnvelope className="text-primary-pink" />
                            <a href="mailto:support@nextstepcounsel.in">support@nextstepcounsel.in</a>
                        </li>
                    </ul>
                </div>
            </div>

            <div className="border-t border-gray-800 pt-8 text-center text-gray-500 text-sm">
                <p>&copy; {new Date().getFullYear()} NextStep Counsel. All rights reserved.</p>
            </div>

            {/* Floating Buttons Container */}
            <div className="fixed bottom-6 right-6 flex flex-col gap-4 z-50">
                {/* Scroll To Top Button */}
                {showScrollToTop && (
                    <button 
                        onClick={scrollToTop}
                        className="bg-primary-pink text-white p-4 rounded-full shadow-lg hover:scale-110 transition animate-fade-in-up flex justify-center items-center"
                        aria-label="Scroll to top"
                    >
                        <FaArrowUp size={20} />
                    </button>
                )}
                
                {/* Floating WhatsApp Button */}
                <a href="https://wa.me/919588928940" target="_blank" rel="noreferrer" className="bg-green-500 text-white p-4 rounded-full shadow-lg hover:scale-110 transition flex justify-center items-center">
                    <FaWhatsapp size={24} />
                </a>
            </div>
        </footer>
    );
};

export default Footer;

