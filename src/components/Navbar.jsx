import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { FaArrowRight, FaSearch, FaBars, FaTimes } from 'react-icons/fa';
import { motion, AnimatePresence } from 'framer-motion';
import SearchModal from './SearchModal';

const Navbar = () => {
    const [isSearchOpen, setIsSearchOpen] = useState(false);

    const navLinks = [
        { name: 'Blog', path: '/blogs' },
        { name: 'Predictor', path: '/predictor' },
        { name: 'Preference List', path: '/neet-pg-preference-list' },
        { name: 'Counselling', path: '/counselling' },
        { name: 'eBooks', path: '/ebooks' },
        { name: 'Connector', path: '/connector' },
        { name: 'About', path: '/about-us' },
    ];

    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
    const location = useLocation();

    // Close menu when route changes
    React.useEffect(() => {
        setIsMobileMenuOpen(false);
    }, [location]);

    return (
        <>
            <nav className="bg-white sticky top-0 z-50 shadow-sm border-b border-gray-100">
                <div className="container mx-auto px-4 py-4 flex justify-between items-center">
                    {/* Logo */}
                    <Link to="/" className="flex flex-col z-50 relative">
                        <img src="/src/assets/sartha-logo-square.png" alt="Sartha" className="h-10 md:h-12 object-contain" />
                    </Link>

                    {/* Desktop Menu */}
                    <div className="hidden md:flex items-center space-x-6">
                        {navLinks.map((link) => (
                            <Link
                                key={link.name}
                                to={link.path}
                                className="text-gray-700 hover:text-primary-pink font-medium transition-colors text-sm"
                            >
                                {link.name}
                            </Link>
                        ))}
                    </div>

                    <div className="flex items-center gap-4">
                        {/* Search Icon */}
                        <button
                            onClick={() => setIsSearchOpen(true)}
                            className="p-2 text-gray-600 hover:text-primary-pink transition-colors rounded-full hover:bg-pink-50"
                            aria-label="Search"
                        >
                            <FaSearch size={18} />
                        </button>

                        {/* Action Button (Desktop) */}
                        <Link to="/login" className="hidden md:flex items-center space-x-2 bg-gradient-primary text-white px-6 py-2.5 rounded-full font-semibold hover:shadow-lg transition transform hover:-translate-y-0.5">
                            <span>Log In</span>
                            <div className="bg-white/20 rounded-full p-1">
                                <FaArrowRight size={12} />
                            </div>
                        </Link>

                        {/* Mobile Menu Button */}
                        <button
                            className="md:hidden text-gray-700 p-2 z-50 relative"
                            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                        >
                            {isMobileMenuOpen ? <FaTimes size={24} /> : <FaBars size={24} />}
                        </button>
                    </div>
                </div>

                {/* Mobile Menu Overlay */}
                <AnimatePresence>
                    {isMobileMenuOpen && (
                        <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="md:hidden bg-white border-t border-gray-100 overflow-hidden absolute top-full left-0 right-0 shadow-lg"
                        >
                            <div className="flex flex-col p-4 space-y-4">
                                {navLinks.map((link) => (
                                    <Link
                                        key={link.name}
                                        to={link.path}
                                        className="text-gray-700 hover:text-primary-pink font-medium text-lg border-b border-gray-50 pb-2"
                                    >
                                        {link.name}
                                    </Link>
                                ))}
                                <Link
                                    to="/login"
                                    className="flex items-center justify-center space-x-2 bg-gradient-primary text-white px-6 py-3 rounded-full font-semibold shadow-md active:scale-95 transition"
                                >
                                    <span>Log In</span>
                                    <FaArrowRight size={12} />
                                </Link>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </nav>

            <SearchModal isOpen={isSearchOpen} onClose={() => setIsSearchOpen(false)} />
        </>
    );
};

export default Navbar;
