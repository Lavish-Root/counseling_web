
import React from 'react';
import { Link } from 'react-router-dom';
import { FaFacebook, FaYoutube, FaWhatsapp, FaEnvelope, FaTelegramPlane, FaInstagram } from 'react-icons/fa';

const Footer = () => {
    return (
        <footer className="bg-dark-bg text-white pt-16 pb-8 border-t border-gray-800">
            <div className="container mx-auto px-4 grid md:grid-cols-4 gap-8 mb-12">
                {/* Brand & About */}
                <div>
                    <Link to="/" className="text-3xl font-bold mb-4 block">NextStep Counsel</Link>
                    <p className="text-gray-400 text-sm mb-6">
                        India’s Trusted Counselling & Career Guidance Platform. We guide students from Registration to Final Admission with complete transparency and expert support.
                    </p>
                    <div className="flex space-x-4">
                        <a href="https://whatsapp.com/channel/0029Vb6rlzt59PwKkP1P9R3A" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition" title="WhatsApp Channel"><FaWhatsapp /></a>
                        <a href="https://youtube.com/@nextstepcounsel?si=uzwipzsPbNRTExy4" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition" title="YouTube"><FaYoutube /></a>
                        <a href="https://t.me/nextstepcounsel1" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition" title="Telegram"><FaTelegramPlane /></a>
                        <a href="https://www.instagram.com/nextstepcounsel01?igsh=MXd0ejllZWlsbm5uYg==" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition" title="Instagram"><FaInstagram /></a>
                        <a href="https://www.facebook.com/share/1KMANqGWhF/" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition" title="Facebook"><FaFacebook /></a>
                    </div>
                </div>

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

            {/* Floating WhatsApp Button */}
            <a href="https://wa.me/919588928940" target="_blank" rel="noreferrer" className="fixed bottom-6 right-6 bg-green-500 text-white p-4 rounded-full shadow-lg hover:scale-110 transition z-50">
                <FaWhatsapp size={24} />
            </a>
        </footer>
    );
};

export default Footer;

