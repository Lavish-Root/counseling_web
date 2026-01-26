import React from 'react';
import { FaStar, FaShoppingCart } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';

const EBooks = () => {
    const navigate = useNavigate();

    const ebooks = [
        {
            id: 'inicet-counseling-ebook',
            title: "INICET COUNSELING E-BOOK",
            description: "Detailed Guide ebook for INICET NOV 2025 Counseling including Previous Year Roundwise-Branchwise Cutoff",
            price: 499,
            originalPrice: 999,
            image: "https://placehold.co/400x500/E15583/ffffff?text=INICET+Guide", // Placeholder until real image is available
            rating: 4.8,
            reviews: 124,
            category: "Medical"
        },
        // Placeholder for future ebooks
        /*
        {
            id: 'neet-ug-guide',
            title: "NEET UG Counselling Master Guide",
            description: "Step-by-step guide for All India & State Quota counselling processes.",
            price: 599,
            originalPrice: 1299,
            image: "https://placehold.co/400x500/8361D0/ffffff?text=NEET+UG",
            rating: 4.9,
            reviews: 210,
            category: "Medical"
        }
        */
    ];

    const handleBuyNow = (ebook) => {
        // For now, we reuse the Cart page logic. 
        // We might need to adjust Cart to handle 'ebook' type items differently if needed, 
        // but for now passing it as a 'plan' works for the prototype.
        navigate('/cart', { state: { plan: { ...ebook, type: 'ebook' } } });
    };

    return (
        <div className="font-sans min-h-screen bg-gray-50">
            {/* Hero Section */}
            <section className="relative bg-gradient-to-r from-gray-900 to-[#1a1025] text-white py-20 lg:py-28">
                <div className="absolute inset-0 bg-[url('/src/assets/bg-pattern.webp')] opacity-5 mix-blend-overlay"></div>
                <div className="container mx-auto px-4 relative z-10 text-center">
                    <h1 className="text-4xl md:text-5xl font-bold mb-4">Our eBooks Collection</h1>
                    <p className="text-xl text-gray-300 max-w-3xl mx-auto">
                        Explore our collection of expertly crafted eBooks to enhance your college admission counselling process.
                    </p>
                </div>
            </section>

            {/* eBooks Grid */}
            <section className="py-16">
                <div className="container mx-auto px-4">
                    <div className="flex justify-center flex-wrap gap-8 max-w-6xl mx-auto">
                        {ebooks.map((ebook, index) => (
                            <div
                                key={index}
                                className="bg-white rounded-2xl shadow-md hover:shadow-xl transition-all duration-300 overflow-hidden border border-gray-100 flex flex-col md:flex-row max-w-2xl w-full"
                            >
                                {/* Image Section */}
                                <div className="md:w-2/5 bg-gray-100 relative overflow-hidden group">
                                    <div className="absolute top-4 left-4 bg-red-500 text-white text-xs font-bold px-2 py-1 rounded">
                                        {Math.round(((ebook.originalPrice - ebook.price) / ebook.originalPrice) * 100)}% OFF
                                    </div>
                                    <img
                                        src={ebook.image}
                                        alt={ebook.title}
                                        className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                                    />
                                </div>

                                {/* Content Section */}
                                <div className="p-6 md:w-3/5 flex flex-col justify-between">
                                    <div>
                                        <div className="flex items-center gap-2 mb-2">
                                            <span className="bg-blue-50 text-blue-600 text-xs font-bold px-2 py-1 rounded uppercase tracking-wide">
                                                {ebook.category}
                                            </span>
                                            <div className="flex items-center text-yellow-400 text-sm">
                                                <FaStar /> <span className="text-gray-500 ml-1 font-medium">{ebook.rating} ({ebook.reviews})</span>
                                            </div>
                                        </div>

                                        <h3 className="text-2xl font-bold text-gray-900 mb-3 leading-tight">{ebook.title}</h3>
                                        <p className="text-gray-600 text-sm leading-relaxed mb-4">
                                            {ebook.description}
                                        </p>
                                    </div>

                                    <div className="mt-4 pt-4 border-t border-gray-100 flex items-center justify-between">
                                        <div>
                                            <span className="text-gray-400 text-sm line-through block">₹{ebook.originalPrice}</span>
                                            <span className="text-3xl font-bold text-gray-900">₹{ebook.price}</span>
                                        </div>
                                        <button
                                            onClick={() => handleBuyNow(ebook)}
                                            className="bg-gradient-to-r from-[#E15583] to-[#8361D0] text-white px-6 py-3 rounded-xl font-bold hover:shadow-lg hover:shadow-purple-200 transition-all flex items-center gap-2 active:scale-95"
                                        >
                                            <FaShoppingCart /> Buy Now
                                        </button>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Empty State / Coming Soon Hint */}
                    {ebooks.length < 3 && (
                        <div className="text-center mt-12 text-gray-400">
                            <p className="italic">More eBooks related to NEET UG, Medical & Engineering Counselling coming soon!</p>
                        </div>
                    )}
                </div>
            </section>
        </div>
    );
};

export default EBooks;
