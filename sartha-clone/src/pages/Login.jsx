import React, { useState, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { GoogleLogin } from '@react-oauth/google';
import NotificationModal from '../components/NotificationModal';

const Login = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [notification, setNotification] = useState({ isOpen: false, type: '', message: '' });
    const emailRef = useRef(null);
    const navigate = useNavigate();

    const closeNotification = () => setNotification({ ...notification, isOpen: false });

    const handleRetry = () => {
        closeNotification();
        setEmail('');
        setPassword('');
        setTimeout(() => {
            if (emailRef.current) emailRef.current.focus();
        }, 100);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';
            const res = await fetch(`${backendUrl}/api/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });
            const data = await res.json();
            if (res.ok) {
                localStorage.setItem('token', data.token);
                localStorage.setItem('user', JSON.stringify(data.user));
                setNotification({ isOpen: true, type: 'success', message: 'Your verification is completed.' });
                setTimeout(() => navigate('/'), 1500);
            } else {
                setNotification({ isOpen: true, type: 'error', message: 'Invalid details' });
            }
        } catch (err) {
            console.error(err);
            setNotification({ isOpen: true, type: 'error', message: 'Something went wrong, please try again.' });
        }
    };

    const handleGoogleSuccess = async (credentialResponse) => {
        try {
            const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';
            const res = await fetch(`${backendUrl}/api/auth/google`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ token: credentialResponse.credential }),
            });

            const data = await res.json();

            if (res.ok) {
                localStorage.setItem('token', data.token);
                localStorage.setItem('user', JSON.stringify(data.user));
                console.log('Google login successful');
                setNotification({ isOpen: true, type: 'success', message: 'Your verification is completed.' });
                setTimeout(() => navigate('/'), 1500);
            } else {
                setNotification({ isOpen: true, type: 'error', message: data.message || 'Google Login failed' });
            }
        } catch (err) {
            console.error('Google login error:', err);
            setNotification({ isOpen: true, type: 'error', message: 'Something went wrong with Google Login, please try again.' });
        }
    };

    const handleGoogleError = () => {
        console.error('Google Login Failed');
        setNotification({ isOpen: true, type: 'error', message: 'Google Login Failed. Please try again.' });
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8 font-sans">
            <NotificationModal
                isOpen={notification.isOpen}
                type={notification.type}
                message={notification.message}
                onClose={closeNotification}
                onRetry={notification.type === 'error' ? handleRetry : undefined}
            />
            <div className="max-w-md w-full space-y-8 bg-white p-10 rounded-2xl shadow-xl">
                <div className="flex flex-col items-center">
                    <Link to="/">
                        {/* <img
                            src="/assets/sartha-logo-square.png"
                            alt="NextStep Counsel"
                            className="h-12 object-contain mb-8"
                        /> */}
                        <span className="text-3xl font-bold text-gray-900 mb-2 block">NextStep Counsel</span>
                    </Link>
                    <h2 className="text-3xl font-bold text-gray-900 mb-2">Welcome Back</h2>
                    <p className="text-gray-500 text-sm">Please enter your details to sign in</p>
                </div>

                <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
                    <div className="space-y-5">
                        <div>
                            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                                Email address
                            </label>
                            <input
                                id="email"
                                name="email"
                                type="email"
                                ref={emailRef}
                                autoComplete="email"
                                required
                                className="appearance-none relative block w-full px-4 py-3 border border-gray-300 placeholder-gray-400 text-gray-900 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-purple focus:border-transparent transition-all sm:text-sm"
                                placeholder="Enter your email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                            />
                        </div>
                        <div>
                            <div className="flex items-center justify-between mb-1">
                                <label htmlFor="password" class="block text-sm font-medium text-gray-700">
                                    Password
                                </label>
                                <Link to="/forgot-password" className="text-sm font-medium text-primary-purple hover:text-primary-pink transition-colors">
                                    Forgot password?
                                </Link>
                            </div>
                            <input
                                id="password"
                                name="password"
                                type="password"
                                autoComplete="current-password"
                                required
                                className="appearance-none relative block w-full px-4 py-3 border border-gray-300 placeholder-gray-400 text-gray-900 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-purple focus:border-transparent transition-all sm:text-sm"
                                placeholder="Enter your password"
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
                            Log in
                        </button>

                        <div className="relative">
                            <div className="absolute inset-0 flex items-center">
                                <div className="w-full border-t border-gray-200"></div>
                            </div>
                            <div className="relative flex justify-center text-sm">
                                <span className="px-2 bg-white text-gray-500">Or continue with</span>
                            </div>
                        </div>

                        <div className="w-full flex justify-center mt-4">
                            <GoogleLogin
                                onSuccess={handleGoogleSuccess}
                                onError={handleGoogleError}
                                useOneTap
                                shape="pill"
                                size="large"
                                text="signin_with"
                                width="100%"
                            />
                        </div>
                    </div>

                    <div className="text-center text-sm">
                        <span className="text-gray-600">Don't have an account? </span>
                        <Link to="/register" className="font-medium text-primary-purple hover:text-primary-pink transition-colors">
                            Register here
                        </Link>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default Login;
