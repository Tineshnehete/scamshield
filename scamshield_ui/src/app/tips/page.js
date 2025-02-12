"use client";
import { useState } from "react";

export default function Tips() {
  const [tips] = useState([
    {
      id: 1,
      title: "How to Avoid Phishing Scams",
      content: "Always verify the sender's email address and look for signs of suspicious links or content before clicking any links or downloading attachments.",
    },
    {
      id: 2,
      title: "Use Strong Passwords",
      content: "Create complex passwords with a mix of letters, numbers, and symbols, and use different passwords for different accounts.",
    },
    {
      id: 3,
      title: "Enable Two-Factor Authentication",
      content: "Enable 2FA wherever possible to add an extra layer of protection to your online accounts.",
    },
    {
      id: 4,
      title: "Beware of Public Wi-Fi",
      content: "Avoid accessing sensitive data like banking information when connected to public Wi-Fi networks. Use a VPN for added security.",
    },
  ]);

  return (
    <div className="min-h-screen p-8 sm:p-20 bg-gray-900 text-gray-300 font-sans">
      <main className="flex flex-col gap-8 items-center sm:items-start w-full">
        <h1 className="text-4xl font-bold text-center text-blue-500 mb-8">
          ScamShield Tips for Staying Safe
        </h1>

        <div className="w-full max-w-3xl">
          {tips.map((tip) => (
            <div
              key={tip.id}
              className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6 shadow-md"
            >
              <h2 className="text-2xl font-bold text-blue-500 mb-2">{tip.title}</h2>
              <p className="text-lg text-gray-300">{tip.content}</p>
            </div>
          ))}
        </div>

        {/* <div className="w-full p-6 bg-gray-800 border border-gray-700 rounded-lg shadow-md">
          <h5 className="mb-2 text-2xl font-bold text-gray-300">
            Need More Help?
          </h5>
          <p className="mb-3 text-gray-300">
            Stay vigilant and aware of the latest scams. For more tips and detailed guides, feel free to explore ScamShield's resources.
          </p>
          <a
            href="/resources"
            className="inline-flex items-center px-3 py-2 text-sm font-medium text-center text-white bg-blue-700 rounded-lg hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300"
          >
            Explore Resources
          </a>
        </div> */}
      </main>
    </div>
  );
}
