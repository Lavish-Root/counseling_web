import React from 'react';
import { FaCheckCircle, FaTimesCircle } from 'react-icons/fa';

const NotificationModal = ({ isOpen, type, message, onClose, onRetry }) => {
    if (!isOpen) return null;

    const isSuccess = type === 'success';

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm transition-opacity">
            <div className="bg-white rounded-2xl shadow-2xl p-8 max-w-sm w-full transform transition-all duration-300 scale-100 flex flex-col items-center text-center">
                {isSuccess ? (
                    <FaCheckCircle className="text-green-500 text-6xl mb-4" />
                ) : (
                    <FaTimesCircle className="text-red-500 text-6xl mb-4" />
                )}

                <h3 className={`text-2xl font-bold mb-2 ${isSuccess ? 'text-green-600' : 'text-red-600'}`}>
                    {isSuccess ? 'Success!' : 'Error'}
                </h3>

                <p className="text-gray-600 mb-6 text-lg font-medium">
                    {message}
                </p>

                {isSuccess ? (
                    <div className="w-full bg-gray-200 rounded-full h-1.5 mt-2 overflow-hidden">
                        <div className="bg-green-500 h-1.5 rounded-full animate-[progress_1.5s_ease-in-out]"></div>
                    </div>
                ) : (
                    <div className="flex gap-4 w-full mt-2">
                        <button
                            onClick={onClose}
                            className="flex-1 py-3 px-4 bg-gray-100 hover:bg-gray-200 text-gray-800 font-bold rounded-xl transition-colors cursor-pointer"
                        >
                            Cancel
                        </button>
                        {onRetry && (
                            <button
                                onClick={onRetry}
                                className="flex-1 py-3 px-4 bg-red-500 hover:bg-red-600 text-white font-bold rounded-xl transition-colors cursor-pointer shadow-lg shadow-red-500/30"
                            >
                                Retry
                            </button>
                        )}
                    </div>
                )}
            </div>
            {/* Add a tiny style block for the progress animation */}
            <style>{`
                @keyframes progress {
                    0% { width: 0%; }
                    100% { width: 100%; }
                }
            `}</style>
        </div>
    );
};

export default NotificationModal;
