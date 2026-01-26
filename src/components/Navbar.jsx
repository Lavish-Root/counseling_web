import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { FaArrowRight, FaSearch } from 'react-icons/fa';
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

    return (
        <>
            <nav className="bg-white sticky top-0 z-50 shadow-sm border-b border-gray-100">
                <div className="container mx-auto px-4 py-4 flex justify-between items-center">
                    {/* Logo */}
                    <Link to="/" className="flex flex-col">
                        <img src="/src/assets/sartha-logo-wide.webp" alt="Sartha" className="h-8 md:h-10 object-contain" />
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

                        {/* Action Button */}
                        <Link to="/login" className="hidden md:flex items-center space-x-2 bg-gradient-primary text-white px-6 py-2.5 rounded-full font-semibold hover:shadow-lg transition transform hover:-translate-y-0.5">
                            <span>Log In</span>
                            <div className="bg-white/20 rounded-full p-1">
                                <FaArrowRight size={12} />
                            </div>
                        </Link>

                        {/* Mobile Menu Button (Placeholder) */}
                        <button className="md:hidden text-gray-700">
                            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16"></path></svg>
                        </button>
                    </div>
                </div>
            </nav>

            <SearchModal isOpen={isSearchOpen} onClose={() => setIsSearchOpen(false)} />
        </>
    );
};

export default Navbar;
