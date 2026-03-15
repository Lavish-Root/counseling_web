import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { GoogleLogin } from '@react-oauth/google';
import NotificationModal from '../components/NotificationModal';

const Register = () => {
    const [step, setStep] = useState(1);
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [otp, setOtp] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [notification, setNotification] = useState({ isOpen: false, type: '', message: '' });
    const navigate = useNavigate();

    const closeNotification = () => setNotification({ ...notification, isOpen: false });

    const handleSendOtp = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        try {
            const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';
            const res = await fetch(`${backendUrl}/api/auth/send-otp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email.trim(), name: name.trim(), isRegistering: true })
            });
            const data = await res.json();
            if (res.ok) {
                setNotification({ isOpen: true, type: 'success', message: 'OTP sent to your email! Please check your inbox.' });
                setTimeout(() => {
                    closeNotification();
                    setStep(2);
                }, 1500);
            } else {
                setNotification({ isOpen: true, type: 'error', message: data.message || 'Failed to send OTP' });
            }
        } catch (err) {
            console.error(err);
            setNotification({ isOpen: true, type: 'error', message: 'Error: ' + (err.message || 'Something went wrong, please try again.') });
        } finally {
            setIsLoading(false);
        }
    };

    const handleVerifyAndRegister = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        try {
            // 1. Verify OTP
            const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';
            const verifyRes = await fetch(`${backendUrl}/api/auth/verify-otp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email.trim(), otp: otp.trim() })
            });
            const verifyData = await verifyRes.json();

            if (!verifyRes.ok) {
                setNotification({ isOpen: true, type: 'error', message: verifyData.message || 'OTP Verification failed' });
                setIsLoading(false);
                return;
            }

            // 2. Register User
            const registerRes = await fetch(`${backendUrl}/api/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: name.trim(), email: email.trim(), password })
            });
            const registerData = await registerRes.json();

            if (registerRes.ok) {
                setNotification({ isOpen: true, type: 'success', message: 'Your verification is completed. Registration successful!' });
                setTimeout(() => navigate('/login'), 1500);
            } else {
                setNotification({ isOpen: true, type: 'error', message: registerData.message || 'Registration failed' });
            }
        } catch (err) {
            console.error(err);
            setNotification({ isOpen: true, type: 'error', message: 'Error: ' + (err.message || 'Something went wrong, please try again.') });
        } finally {
            setIsLoading(false);
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
        console.error('Google Server Error');
        setNotification({ isOpen: true, type: 'error', message: 'Google Login Failed. Please try again.' });
    };


    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8 font-sans">
            <NotificationModal
                isOpen={notification.isOpen}
                type={notification.type}
                message={notification.message}
                onClose={closeNotification}
                onRetry={notification.type === 'error' ? closeNotification : undefined}
            />
            <div className="max-w-md w-full space-y-8 bg-white p-10 rounded-2xl shadow-xl">
                <div className="flex flex-col items-center">
                    <Link to="/">
                        <span className="text-3xl font-bold text-gray-900 mb-2 block">NextStep Counsel</span>
                    </Link>
                    <h2 className="text-xl font-bold text-gray-900 mb-1">{step === 1 ? 'Create an Account' : 'Verify Your Email'}</h2>
                    {step === 2 && <p className="text-gray-500 text-sm text-center">We've sent a 6-digit code to {email}</p>}
                </div>

                <form className="mt-8 space-y-6" onSubmit={step === 1 ? handleSendOtp : handleVerifyAndRegister}>
                    <div className="space-y-5">
                        {step === 1 && (
                            <>
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
                                        value={name}
                                        onChange={(e) => setName(e.target.value)}
                                        disabled={isLoading}
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
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        disabled={isLoading}
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
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        disabled={isLoading}
                                    />
                                </div>
                            </>
                        )}

                        {step === 2 && (
                            <div>
                                <label htmlFor="otp" className="block text-sm font-medium text-gray-700 mb-1">
                                    Verification Code
                                </label>
                                <input
                                    id="otp"
                                    name="otp"
                                    type="text"
                                    required
                                    maxLength="6"
                                    className="appearance-none text-center tracking-widest text-xl font-mono relative block w-full px-4 py-3 border border-gray-300 placeholder-gray-400 text-gray-900 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-purple focus:border-transparent transition-all sm:text-sm"
                                    placeholder="000000"
                                    value={otp}
                                    onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))}
                                    disabled={isLoading}
                                />
                                <div className="mt-2 text-right">
                                    <button
                                        type="button"
                                        onClick={() => setStep(1)}
                                        className="text-sm text-primary-purple hover:underline"
                                    >
                                        Change email
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>

                    <div className="space-y-4">
                        <button
                            type="submit"
                            disabled={isLoading}
                            className={`group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-semibold rounded-full text-white bg-gradient-to-r from-[#E15583] to-[#8361D0] hover:shadow-lg transform transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-purple ${isLoading ? 'opacity-70 cursor-not-allowed' : 'hover:-translate-y-0.5 cursor-pointer'}`}
                        >
                            {isLoading ? 'Processing...' : (step === 1 ? 'Verify Email' : 'Complete Registration')}
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
                                text="signup_with"
                                width="100%"
                            />
                        </div>
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
