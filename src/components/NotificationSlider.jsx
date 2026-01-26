import React from 'react';
import { Swiper, SwiperSlide } from 'swiper/react';
import { Autoplay } from 'swiper/modules';
import 'swiper/css';

const NotificationSlider = () => {
    const notifications = [
        "MCC NEET PG 2024: Round-1 Final Result Declared.",
        "UP NEET UG 2024: Special Stray Vacancy Round Schedule Out.",
        "Check Out Our Latest College Predictor Tool!"
    ];

    return (
        <div className="bg-gradient-primary text-white text-xs md:text-sm py-2 relative z-50">
            <div className="container mx-auto px-4 flex items-center justify-between">
                <span className="font-bold bg-white/20 px-2 py-0.5 rounded text-[10px] mr-4 hidden md:inline-block">NEW</span>
                <Swiper
                    modules={[Autoplay]}
                    spaceBetween={50}
                    slidesPerView={1}
                    loop={true}
                    autoplay={{ delay: 3000, disableOnInteraction: false }}
                    className="w-full"
                >
                    {notifications.map((note, index) => (
                        <SwiperSlide key={index} className="text-center font-medium">
                            {note}
                        </SwiperSlide>
                    ))}
                </Swiper>
            </div>
        </div>
    );
};

export default NotificationSlider;
