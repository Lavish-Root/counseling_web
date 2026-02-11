import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { FcGoogle } from 'react-icons/fc';

const Register = () => {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const navigate = useNavigate();

    const handleSubmit = (e) => {
        e.preventDefault();
        console.log("Register attempt:", { name, email, password });
        // Simulate registration success
        alert('Registration successful! Please log in.');
        navigate('/login');
    };

    const handleGoogleSignup = () => {
        // Reuse the mock Google login logic
        const width = 500;
        const height = 600;
        const left = (window.screen.width / 2) - (width / 2);
        const top = (window.screen.height / 2) - (height / 2);

        window.open(
            '/mock-login',
            'NextStep Counsel Google Signup',
            `width=${width},height=${height},top=${top},left=${left}`
        );

        // Listen for success message (reusing the login listener logic for simplicity in this mock)
        const handleMessage = (event) => {
            if (event.origin !== window.location.origin) return;
            if (event.data && event.data.type === 'GOOGLE_LOGIN_SUCCESS') {
                navigate('/');
            }
        };
        window.addEventListener('message', handleMessage);
        // Note: Clean up listener is tricky here without useEffect, but for mock it's okay-ish
        // Better to use the useEffect approach like in Login.jsx, but keeping it simple for now. 
        // Actually, let's just create a proper useEffect for consistency.
    };

    // Proper listener
    React.useEffect(() => {
        const handleMessage = (event) => {
            if (event.origin !== window.location.origin) return;
            if (event.data && event.data.type === 'GOOGLE_LOGIN_SUCCESS') {
                navigate('/');
            }
        };
        window.addEventListener('message', handleMessage);
        return () => window.removeEventListener('message', handleMessage);
    }, [navigate]);


    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8 font-sans">
            <div className="max-w-md w-full space-y-8 bg-white p-10 rounded-2xl shadow-xl">
                <div className="flex flex-col items-center">
                    <Link to="/">
                        {/* <img
                            src="/assets/sartha-logo-square.png"
                            alt="NextStep Counsel"
                            className="h-16 object-contain mb-2"
                        /> */}
                        <span className="text-3xl font-bold text-gray-900 mb-2 block">NextStep Counsel</span>
                    </Link>
                    {/* Tagline or minimal header if needed, screenshot shows just logo mostly, but let's match Login structure cleanly */}
                </div>

                <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
                    <div className="space-y-5">
                        <div>
                            <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-1">
                                Name
                            </label>
                            <input
                                id="name"
                                name="name"
                                type="text"
                                required
                                className="appearance-none relative block w-full px-4 py-3 border border-gray-300 placeholder-gray-400 text-gray-900 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-purple focus:border-transparent transition-all sm:text-sm"
                                placeholder=""
                                value={name}
                                onChange={(e) => setName(e.target.value)}
                            />
                        </div>

                        <div>
                            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                                Email address
                            </label>
                            <input
                                id="email"
                                name="email"
                                type="email"
                                autoComplete="email"
                                required
                                className="appearance-none relative block w-full px-4 py-3 border border-gray-300 placeholder-gray-400 text-gray-900 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-purple focus:border-transparent transition-all sm:text-sm"
                                placeholder=""
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                            />
                        </div>
                        <div>
                            <label htmlFor="password" class="block text-sm font-medium text-gray-700 mb-1">
                                Create Password
                            </label>
                            <input
                                id="password"
                                name="password"
                                type="password"
                                required
                                className="appearance-none relative block w-full px-4 py-3 border border-gray-300 placeholder-gray-400 text-gray-900 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-purple focus:border-transparent transition-all sm:text-sm"
                                placeholder=""
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            />
                        </div>
                    </div>

                    <div className="space-y-4">
                        <button
                            type="submit"
                            className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-semibold rounded-full text-white bg-gradient-to-r from-[#E15583] to-[#8361D0] hover:shadow-lg transform hover:-translate-y-0.5 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-purple cursor-pointer"
                        >
                            Register
                        </button>

                        <div className="relative">
                            <div className="absolute inset-0 flex items-center">
                                <div className="w-full border-t border-gray-200"></div>
                            </div>
                            <div className="relative flex justify-center text-sm">
                                <span className="px-2 bg-white text-gray-500">Or continue with</span>
                            </div>
                        </div>

                        <button
                            type="button"
                            onClick={handleGoogleSignup}
                            className="w-full flex justify-center items-center gap-3 py-3 px-4 border border-gray-300 rounded-full shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-purple cursor-pointer"
                        >
                            <FcGoogle className="h-5 w-5" />
                            Sign up with Google
                        </button>
                    </div>

                    <div className="text-center text-sm">
                        <span className="text-gray-600">Already have an account? </span>
                        <Link to="/login" className="font-bold text-[#802D62] hover:text-[#E15583] transition-colors">
                            Login
                        </Link>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default Register;
