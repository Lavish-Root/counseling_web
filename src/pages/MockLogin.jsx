import React, { useEffect } from 'react';
import { FaGoogle } from 'react-icons/fa';

const MockLogin = () => {
    useEffect(() => {
        // Simulate network delay for authentication
        const timer = setTimeout(() => {
            // Send success message to parent window
            if (window.opener) {
                window.opener.postMessage({ type: 'GOOGLE_LOGIN_SUCCESS' }, window.location.origin);
                window.close();
            } else {
                // Fallback if opened directly
                alert('This is a mock login page. It should be opened via the Login page.');
            }
        }, 2000);

        return () => clearTimeout(timer);
    }, []);

    return (
        <div className="min-h-screen flex flex-col items-center justify-center bg-white font-sans">
            <div className="p-8 text-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-purple mx-auto mb-6"></div>
                <h2 className="text-xl font-semibold text-gray-800 mb-2">Connecting to Google...</h2>
                <p className="text-gray-500 text-sm">Please wait while we securely sign you in.</p>
            </div>
        </div>
    );
};

export default MockLogin;
