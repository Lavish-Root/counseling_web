import React, { useEffect, useState } from 'react';
import { useLocation, Link } from 'react-router-dom';
import { FaTrash, FaArrowLeft, FaShieldAlt } from 'react-icons/fa';

const Cart = () => {
    const location = useLocation();
    const [cartItem, setCartItem] = useState(null);

    useEffect(() => {
        if (location.state && location.state.plan) {
            setCartItem(location.state.plan);
            // In a real app, you might save this to localStorage or Context
            // e.g., localStorage.setItem('cart', JSON.stringify(location.state.plan));
        }
    }, [location]);

    if (!cartItem) {
        return (
            <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-4">
                <div className="bg-white p-8 rounded-2xl shadow-xl text-center max-w-md w-full border border-gray-100">
                    <img src="https://cdn-icons-png.flaticon.com/512/11329/11329060.png" alt="Empty Cart" className="w-32 h-32 mx-auto mb-6 opacity-80" />
                    <h2 className="text-2xl font-bold text-gray-900 mb-2">Your Cart is Empty</h2>
                    <p className="text-gray-500 mb-8">Looks like you haven't added any counselling plans yet.</p>
                    <Link to="/counselling" className="inline-block w-full bg-gradient-to-r from-[#E15583] to-[#8361D0] text-white py-3 rounded-xl font-bold hover:shadow-lg transition transform hover:-translate-y-1">
                        Browse Counselling Plans
                    </Link>
                </div>
            </div>
        );
    }

    const price = parseInt(cartItem.price);
    const gstRate = 0.18;
    const gstAmount = price * gstRate;
    const total = price + gstAmount;

    return (
        <div className="min-h-screen bg-gray-50 py-12 font-sans">
            <div className="container mx-auto px-4 max-w-6xl">
                <div className="flex items-center gap-2 mb-8 text-gray-500 hover:text-gray-900 transition">
                    <FaArrowLeft />
                    <Link to="/counselling/mbbs">Back to Plans</Link>
                </div>

                <h1 className="text-3xl font-bold text-gray-900 mb-8">Your Cart</h1>

                <div className="grid lg:grid-cols-3 gap-8">
                    {/* Cart Items Column */}
                    <div className="lg:col-span-2 space-y-4">
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-100">
                            <div className="flex justify-between items-start">
                                <div>
                                    <p className="text-xs font-bold text-primary-purple uppercase tracking-wider mb-1">Counselling Service</p>
                                    <h3 className="text-xl font-bold text-gray-900 mb-2">{cartItem.title}</h3>
                                    <p className="text-gray-500 text-sm max-w-md">{cartItem.subtitle}</p>
                                </div>
                                <button
                                    onClick={() => setCartItem(null)}
                                    className="text-gray-400 hover:text-red-500 transition p-2 hover:bg-red-50 rounded-full"
                                    title="Remove item"
                                >
                                    <FaTrash />
                                </button>
                            </div>
                            <div className="mt-6 pt-6 border-t border-gray-100 flex justify-between items-center">
                                <span className="font-semibold text-gray-600">Price</span>
                                <span className="text-xl font-bold text-gray-900">₹ {price.toLocaleString()}</span>
                            </div>
                        </div>

                        {/* Trust Badges */}
                        <div className="grid sm:grid-cols-3 gap-4">
                            <div className="flex items-center gap-3 bg-blue-50/50 p-4 rounded-xl border border-blue-100">
                                <FaShieldAlt className="text-blue-500 text-xl" />
                                <div>
                                    <h4 className="font-bold text-gray-900 text-sm">Secure Payment</h4>
                                    <p className="text-gray-500 text-xs">256-bit SSL Encrypted</p>
                                </div>
                            </div>
                            {/* Add more trust badges as needed */}
                        </div>
                    </div>

                    {/* Order Summary Column */}
                    <div className="lg:col-span-1">
                        <div className="bg-white p-6 rounded-2xl shadow-lg border border-gray-100 sticky top-24">
                            <h3 className="text-lg font-bold text-gray-900 mb-6">Order Summary</h3>

                            <div className="space-y-4 mb-6">
                                <div className="flex justify-between text-gray-600">
                                    <span>Subtotal</span>
                                    <span>₹ {price.toLocaleString()}</span>
                                </div>
                                <div className="flex justify-between text-gray-600">
                                    <span>GST (18%)</span>
                                    <span>₹ {gstAmount.toLocaleString()}</span>
                                </div>
                                <div className="border-t border-gray-100 pt-4 flex justify-between items-center">
                                    <span className="font-bold text-gray-900 text-lg">Total</span>
                                    <span className="font-bold text-primary-pink text-2xl">₹ {total.toLocaleString()}</span>
                                </div>
                            </div>

                            <button className="w-full bg-gradient-to-r from-[#E15583] to-[#8361D0] text-white py-4 rounded-xl font-bold text-lg hover:shadow-xl transition transform hover:-translate-y-1 active:scale-95 mb-4 cursor-pointer">
                                Proceed to Payment
                            </button>

                            <p className="text-center text-xs text-gray-400">
                                By proceeding, you agree to our Terms of Service and Refund Policy.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Cart;
