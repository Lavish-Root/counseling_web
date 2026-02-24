import React from 'react';
import { FaUserGraduate, FaChalkboardTeacher, FaUniversity, FaSmile } from 'react-icons/fa';

const StatsDisplay = () => {
    const stats = [
        { label: "Students Counseled", value: "10k+", icon: <FaUserGraduate /> },
        { label: "Expert Mentors", value: "50+", icon: <FaChalkboardTeacher /> },
        { label: "Partner Colleges", value: "100+", icon: <FaUniversity /> },
        { label: "Happy Faces", value: "98%", icon: <FaSmile /> }
    ];

    return (
        <div className="relative -mt-16 z-30 container mx-auto px-4">
            <div className="bg-white/90 backdrop-blur-md rounded-2xl shadow-xl border border-white/20 p-8 md:p-12">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-8 divide-x divide-gray-100">
                    {stats.map((stat, index) => (
                        <div key={index} className="text-center group p-2">
                            <div className="text-3xl md:text-4xl font-black bg-gradient-to-r from-[#E15583] to-[#8361D0] bg-clip-text text-transparent mb-2 group-hover:scale-110 transition-transform duration-300">
                                {stat.value}
                            </div>
                            <div className="flex items-center justify-center gap-2 text-gray-500 font-medium text-sm md:text-base">
                                <span className="text-[#8361D0] opacity-50 group-hover:opacity-100 transition-opacity">{stat.icon}</span>
                                {stat.label}
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default StatsDisplay;
