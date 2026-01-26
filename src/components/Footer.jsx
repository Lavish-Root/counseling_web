
import React from 'react';
import { Link } from 'react-router-dom';
import { FaFacebook, FaTwitter, FaInstagram, FaYoutube, FaWhatsapp, FaPhone, FaEnvelope, FaMapMarkerAlt } from 'react-icons/fa';

const Footer = () => {
    return (
        <footer className="bg-dark-bg text-white pt-16 pb-8 border-t border-gray-800">
            <div className="container mx-auto px-4 grid md:grid-cols-4 gap-8 mb-12">
                {/* Brand & About */}
                <div>
                    <Link to="/" className="text-3xl font-bold mb-4 block">NextStep Counsel</Link>
                    <p className="text-gray-400 text-sm mb-6">
                        The Ultimate College Guidance and Counselling Platform for NEET & CUET. We are with you, till the end!
                    </p>
                    <div className="flex space-x-4">
                        <a href="https://instagram.com/sartha.in" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition"><FaInstagram /></a>
                        <a href="https://youtube.com/@SarthaEducation" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition"><FaYoutube /></a>
                        <a href="https://twitter.com/sartha_in" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition"><FaTwitter /></a>
                        <a href="https://facebook.com/sartha.in" target="_blank" rel="noreferrer" className="bg-white/10 p-2 rounded-full hover:bg-primary-pink transition"><FaFacebook /></a>
                    </div>
                </div>

                {/* Quick Links */}
                <div>
                    <h4 className="font-bold text-lg mb-6">Quick Links</h4>
                    <ul className="space-y-3 text-sm text-gray-400">
                        <li><a href="https://nta.ac.in/" target="_blank" rel="noreferrer" className="hover:text-primary-pink transition">NTA Official Website</a></li>
                        <li><a href="https://mcc.nic.in/" target="_blank" rel="noreferrer" className="hover:text-primary-pink transition">MCC Counselling</a></li>
                        <li><a href="https://aaccc.gov.in/" target="_blank" rel="noreferrer" className="hover:text-primary-pink transition">AYUSH Counselling</a></li>
                        <li><Link to="/terms" className="hover:text-primary-pink transition">Terms & Conditions</Link></li>
                        <li><Link to="/privacy" className="hover:text-primary-pink transition">Privacy Policy</Link></li>
                        <li><Link to="/refund" className="hover:text-primary-pink transition">Refund Policy</Link></li>
                    </ul>
                </div>

                {/* Services */}
                <div>
                    <h4 className="font-bold text-lg mb-6">Our Services</h4>
                    <ul className="space-y-3 text-sm text-gray-400">
                        <li><Link to="/counselling" className="hover:text-primary-pink transition">Personalised Counselling</Link></li>
                        <li><Link to="/predictor" className="hover:text-primary-pink transition">College Predictor</Link></li>
                        <li><Link to="/ebooks" className="hover:text-primary-pink transition">Counselling eBooks</Link></li>
                        <li><Link to="/connector" className="hover:text-primary-pink transition">NextStep Counsel Connector</Link></li>
                    </ul>
                </div>

                {/* Contact */}
                <div>
                    <h4 className="font-bold text-lg mb-6">Get In Touch</h4>
                    <ul className="space-y-4 text-sm text-gray-400">
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
            <a href="https://wa.me/91701264008" target="_blank" rel="noreferrer" className="fixed bottom-6 right-6 bg-green-500 text-white p-4 rounded-full shadow-lg hover:scale-110 transition z-50">
                <FaWhatsapp size={24} />
            </a>
        </footer>
    );
};

export default Footer;

