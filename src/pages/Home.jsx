import React from 'react';
import HeroSection from '../components/HeroSection';
import NotificationSlider from '../components/NotificationSlider';
import StatsDisplay from '../components/StatsDisplay';
import OneOnOneSection from '../components/HomeSections/OneOnOneSection';
import PredictorSection from '../components/HomeSections/PredictorSection';
import EBooksSection from '../components/HomeSections/EBooksSection';
import ConnectorSection from '../components/HomeSections/ConnectorSection';
import FeaturedInSection from '../components/HomeSections/FeaturedInSection';

const Home = () => {
    return (
        <div className="font-sans">
            <NotificationSlider />
            <HeroSection />
            <StatsDisplay />
            <FeaturedInSection />
            <OneOnOneSection />
            <PredictorSection />
            <EBooksSection />
            <ConnectorSection />

            {/* CTA Section */}
            <div className="bg-gradient-primary py-16 text-center text-white">
                <h2 className="text-3xl font-bold mb-4">Ready to start your journey?</h2>
                <p className="mb-8 opacity-90">Join thousands of students who trust Sartha.</p>
                <button className="bg-white text-primary-purple px-8 py-3 rounded-full font-bold hover:shadow-lg hover:scale-105 transition">
                    Get Started Now
                </button>
            </div>
        </div>
    );
};

export default Home;
