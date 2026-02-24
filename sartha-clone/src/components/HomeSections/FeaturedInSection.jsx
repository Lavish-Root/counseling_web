import React from 'react';

const FeaturedInSection = () => {
    return (
        <section className="py-10 border-t border-gray-100">
            <div className="container mx-auto px-4 text-center">
                <p className="text-gray-400 font-bold tracking-widest text-sm mb-8 uppercase">Featured In</p>
                <div className="relative overflow-hidden w-full max-w-4xl mx-auto">
                    <div className="flex w-[200%] animate-scroll hover:pause">
                        {/* First Set of Logos */}
                        <div className="flex w-1/2 justify-around items-center gap-8 md:gap-16 opacity-80 grayscale hover:grayscale-0 transition-all duration-500">
                            <img src="/assets/ahmedabad-mirror.png" alt="Ahmedabad Mirror" className="h-8 md:h-12 object-contain" />
                            <img src="/assets/josh-talks.png" alt="Josh Talks" className="h-8 md:h-12 object-contain" />
                            <img src="/assets/ecell-logo.png" alt="E-Cell IIT Bombay" className="h-8 md:h-12 object-contain" />
                            <img src="/assets/medium-logo.png" alt="Medium" className="h-8 md:h-12 object-contain" />
                        </div>
                        {/* Duplicate Set for Infinite Scroll */}
                        <div className="flex w-1/2 justify-around items-center gap-8 md:gap-16 opacity-80 grayscale hover:grayscale-0 transition-all duration-500">
                            <img src="/assets/ahmedabad-mirror.png" alt="Ahmedabad Mirror" className="h-8 md:h-12 object-contain" />
                            <img src="/assets/josh-talks.png" alt="Josh Talks" className="h-8 md:h-12 object-contain" />
                            <img src="/assets/ecell-logo.png" alt="E-Cell IIT Bombay" className="h-8 md:h-12 object-contain" />
                            <img src="/assets/medium-logo.png" alt="Medium" className="h-8 md:h-12 object-contain" />
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default FeaturedInSection;
