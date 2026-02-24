import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaSearch, FaTimes, FaBuilding, FaArrowRight } from 'react-icons/fa';
import { collegesData } from '../data/colleges';

const SearchModal = ({ isOpen, onClose }) => {
    const [searchQuery, setSearchQuery] = useState('');
    const [filteredColleges, setFilteredColleges] = useState([]);
    const inputRef = useRef(null);

    // Filter results when query changes
    useEffect(() => {
        if (searchQuery.trim() === '') {
            setFilteredColleges([]);
            return;
        }

        const results = collegesData.filter(college =>
            college.toLowerCase().includes(searchQuery.toLowerCase())
        );
        // Limit results for better performance/UI
        setFilteredColleges(results.slice(0, 50));
    }, [searchQuery]);

    // Auto-focus input when modal opens
    useEffect(() => {
        if (isOpen && inputRef.current) {
            setTimeout(() => {
                inputRef.current.focus();
            }, 100);
        }
    }, [isOpen]);

    // Close on Escape key
    useEffect(() => {
        const handleEsc = (e) => {
            if (e.key === 'Escape') onClose();
        };
        window.addEventListener('keydown', handleEsc);
        return () => window.removeEventListener('keydown', handleEsc);
    }, [onClose]);

    if (!isOpen) return null;

    return (
        <AnimatePresence>
            {isOpen && (
                <div className="fixed inset-0 z-[100] overflow-hidden">
                    {/* Backdrop */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        onClick={onClose}
                        className="absolute inset-0 bg-black/40 backdrop-blur-sm"
                    />

                    {/* Modal Content */}
                    <motion.div
                        initial={{ opacity: 0, y: -50 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -50 }}
                        transition={{ type: "spring", damping: 25, stiffness: 300 }}
                        className="relative w-full max-w-2xl mx-auto mt-20 px-4"
                    >
                        <div className="bg-white rounded-2xl shadow-2xl overflow-hidden border border-gray-100 flex flex-col max-h-[70vh]">
                            {/* Header / Input Area */}
                            <div className="flex items-center p-4 border-b border-gray-100 bg-gray-50/50">
                                <FaSearch className="text-gray-400 text-lg ml-2" />
                                <input
                                    ref={inputRef}
                                    type="text"
                                    placeholder="Search for colleges, exams, or courses..."
                                    className="flex-1 bg-transparent border-none outline-none px-4 text-lg text-gray-800 placeholder-gray-400 h-10"
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                />
                                <button
                                    onClick={onClose}
                                    className="p-2 hover:bg-gray-200 rounded-full text-gray-500 transition-colors"
                                >
                                    <FaTimes />
                                </button>
                            </div>

                            {/* Results Area */}
                            <div className="overflow-y-auto custom-scrollbar bg-white">
                                {searchQuery.trim() === '' ? (
                                    <div className="p-8 text-center text-gray-400">
                                        <p className="text-sm">Start typing to search...</p>
                                    </div>
                                ) : filteredColleges.length > 0 ? (
                                    <div className="py-2">
                                        <div className="px-4 py-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                                            Results
                                        </div>
                                        {filteredColleges.map((college, index) => (
                                            <div
                                                key={index}
                                                className="px-4 py-3 hover:bg-purple-50 cursor-pointer transition-colors flex items-center gap-3 border-b border-gray-50 last:border-none group"
                                                onClick={() => {
                                                    console.log("Selected:", college);
                                                    // Add navigation logic here if needed
                                                    onClose();
                                                }}
                                            >
                                                <div className="w-8 h-8 rounded-lg bg-purple-100 text-purple-600 flex items-center justify-center shrink-0">
                                                    <FaBuilding className="text-sm" />
                                                </div>
                                                <div className="flex-1 text-sm font-medium text-gray-700 group-hover:text-purple-700">
                                                    {college}
                                                </div>
                                                <FaArrowRight className="text-gray-300 group-hover:text-purple-400 opacity-0 group-hover:opacity-100 transition-all -translate-x-2 group-hover:translate-x-0" />
                                            </div>
                                        ))}
                                    </div>
                                ) : (
                                    <div className="p-8 text-center text-gray-500">
                                        <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                                            <FaSearch className="text-gray-400 text-xl" />
                                        </div>
                                        <p className="font-medium">No results found</p>
                                        <p className="text-sm text-gray-400 mt-1">Try searching for a different keyword</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    </motion.div>
                </div>
            )}
        </AnimatePresence>
    );
};

export default SearchModal;
