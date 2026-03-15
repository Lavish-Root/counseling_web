import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { FaGraduationCap } from 'react-icons/fa';

const PageLoader = () => {
  const [loading, setLoading] = useState(false);
  const location = useLocation();

  useEffect(() => {
    setLoading(true);
    const timer = setTimeout(() => {
      setLoading(false);
    }, 1000);

    return () => clearTimeout(timer);
  }, [location.pathname]);

  if (!loading) return null;

  return (
    <div className="fixed inset-0 z-[99999] flex items-center justify-center bg-white/95 backdrop-blur-md transition-all duration-300">
      <div className="flex flex-col items-center">
        <FaGraduationCap className="text-6xl md:text-8xl text-[#11316B] animate-pulse drop-shadow-lg" />
        <div className="mt-8 flex space-x-3">
          <div className="w-4 h-4 bg-[#11316B] rounded-full animate-bounce" style={{ animationDelay: '0s' }}></div>
          <div className="w-4 h-4 bg-[#11316B] rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
          <div className="w-4 h-4 bg-[#11316B] rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
        </div>
      </div>
    </div>
  );
};

export default PageLoader;
