import React from 'react';

const AboutUs = () => {
  return (
    <div className="bg-gray-900 mt-3 text-gray-300 ">
      <header className="bg-gray-800 text-center py-12">
        <h1 className="text-4xl font-bold text-white">About ScamShield</h1>
        <p className="text-lg mt-4">
          At ScamShield, we are committed to making the internet a safer place by empowering users 
          to identify and avoid online scams. Our mission is to provide a seamless and reliable 
          tool that evaluates the credibility of URLs and protects users from potential threats.
        </p>
      </header>
      <section className="py-10 px-6 md:px-12">
        <h2 className="text-2xl font-semibold text-blue-400">Our Mission</h2>
        <p className="mt-4">
          The rise of phishing attacks and malicious websites has made online security more 
          critical than ever. ScamShield was created to address this growing concern, providing 
          everyone with the ability to make informed decisions about the links they interact with.
        </p>
      </section>
      <section className="py-10 px-6 md:px-12 bg-gray-800">
        <h2 className="text-2xl font-semibold text-blue-400">Our Journey</h2>
        <p className="mt-4">
          What started as a simple idea to combat phishing has evolved into a comprehensive 
          solution. Leveraging cutting-edge technology, ScamShield continuously adapts to the 
          ever-changing threat landscape, ensuring our users always stay one step ahead.
        </p>
      </section>
      <section className="py-10 px-6 md:px-12">
        <h2 className="text-2xl font-semibold text-blue-400">Our Core Values</h2>
        <p className="mt-4">
          Transparency, innovation, and user safety are the pillars of ScamShield. We believe in 
          equipping every individual with tools to navigate the internet securely and confidently.
        </p>
      </section>
      
     
    </div>
  );
};

export default AboutUs;
