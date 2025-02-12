"use client";
import ReportUrlForm from "@/components/reporturlform";
import Scanner from "@/utils/scanner";
import Image from "next/image";
import { useState } from "react";

export default function Home() {
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [url, setUrl] = useState("");

  console.log(report?.trust_score);

  const handleSubmit = async (event) => {
    event.preventDefault();
    const url = event.target.url.value;
    setUrl(url);
    setError(null);
    setIsLoading(true);
    await Scanner.scan(url)
      .then((data) => {
        console.log(data);
        setReport(data?.report);
      })
      .catch((error) => {
        if (error.response) {
          setError(error.response.data.error);
        }
      })
      .finally(() => {
        setIsLoading(false);
      });
  };

  return (
    <div className="grid grid-rows-[20px_1fr_20px] items-center justify-items-center mt-4 p-8 pb-20 gap-16 sm:p-20 bg-gray-900 text-gray-300 font-[family-name:var(--font-geist-sans)]">
      <main className="flex flex-col gap-8 row-start-2 items-center sm:items-start w-full">
        <form
          className="flex flex-col w-full gap-4 items-center sm:items-start"
          onSubmit={handleSubmit}
        >
          <label htmlFor="url" className="text-lg font-medium">
            Enter a URL to check if {"it's"} a scam
          </label>
          <div className="flex w-full gap-4">
            <input
              className="flex-grow block p-4 text-gray-800 text-lg border border-gray-600 rounded-md focus:ring-2 focus:ring-blue-500 focus:outline-none"
              type="url"
              id="url"
              name="url"
              placeholder="https://example.com"
              disabled={isLoading}
            />
            <button
              className="px-6 py-3 text-lg text-white bg-blue-600 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
              type="submit"
              disabled={isLoading}
            >
              Check
            </button>
          </div>
        </form>
        {error && (
          <div className="flex w-full gap-4 p-4 bg-red-800 border border-red-500 rounded-md">
            <p className="text-red-200">{error}</p>
          </div>
        )}
        {!isLoading && report && (
          <div className="flex w-full flex-col gap-4 items-center sm:items-start">
            <h2 className="text-2xl font-semibold text-blue-400">Scan Report</h2>
            <div
              className="flex flex-col gap-4 p-4 w-full shadow-md rounded-md"
              style={{
                border: `2px solid hsl(${120 * ((report?.trust_score || 0) / 100)}, 100%, 50%)`,
                backgroundColor: `hsla(${120 * ((report?.trust_score || 0) / 100)}, 100%, 50%, 0.05)`,
              }}
            >
              <div className="text-lg mx-auto text-center font-semibold">{url}</div>
              <div className="text-4xl mx-auto text-center font-bold text-white">
                {(report?.trust_score || 0)}
              </div>
              <p className="text-center">
                {(report?.trust_score || 0) < 25
                  ? "This website is likely a scam."
                  : (report?.trust_score || 0) < 50
                    ? "This website may be a scam."
                    : (report?.trust_score || 0) < 75
                      ? "This website looks safe."
                      : "This website is safe."}
              </p>
            </div>
            <div className="grid grid-cols-3 gap-4 w-full">
              {Object.entries(report).map(([key, value]) => {
                if (typeof value === "object") return null;
                return (
                  <div
                    key={key}
                    className="flex flex-col gap-2 p-4 border border-gray-600 rounded-md"
                  >
                    <h3 className="text-lg font-semibold capitalize text-blue-400">
                      {key.replace("_", " ")}
                    </h3>
                    <p>{value}</p>
                  </div>
                );
              })}
            </div>
            <div className="flex w-full flex-col gap-2 p-4 border border-gray-600 rounded-md">
              <h3 className="text-lg font-semibold capitalize text-blue-400">
                SSL Details
              </h3>
              <table className="w-full text-sm">
                <tbody>
                  {Object.entries(report.ssl).map(([key, value]) => (
                    <tr key={key}>
                      <td className="font-semibold">{key.replace("_", " ")}</td>
                      <td>{value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex w-full flex-col gap-2 p-4 border border-gray-600 rounded-md">
              <h3 className="text-lg font-semibold capitalize text-blue-400">
                Whois Details
              </h3>
              <table className="w-full text-sm">
                <tbody>
                  {Object.entries(report.whois).map(([key, value]) => (
                    <tr key={key}>
                      <td className="font-semibold">{key.replace("_", " ")}</td>
                      <td>{value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <ReportUrlForm url={url} />
          </div>
        )}
        {isLoading && (
          <div className="flex w-full gap-4 p-4 bg-blue-800 border border-blue-500 rounded-md">
            <p className="text-blue-200">Generating Report...</p>
          </div>
        )}
        
        <div className="home-content flex flex-col gap-8 items-center text-center sm:text-left sm:items-start p-6 sm:p-12">
          <section className="welcome">
            <h1 className="text-4xl font-bold text-white mb-4">Welcome to ScamShield</h1>
            <p className="text-lg text-gray-300">
              In today’s digital landscape, online threats are more prevalent than ever. Phishing scams, malicious websites,
              and fraudulent URLs put your personal information and finances at risk. ScamShield is here to bridge the gap
              between safety and convenience, providing you with powerful tools to identify scams and safeguard your digital journey.
            </p>
          </section>

          <section className="features">
            <h2 className="text-3xl font-semibold text-white mb-4">What Sets Us Apart?</h2>
            <p className="text-lg text-gray-300">
              At ScamShield, we use cutting-edge technology to analyze websites for potential risks. Our advanced algorithms evaluate
              a wide range of parameters, from SSL certificates to domain reputation. With our user-friendly interface, you can easily
              understand the trustworthiness of any website at a glance.
            </p>
          </section>

          <section className="how-it-works">
            <h2 className="text-3xl font-semibold text-white mb-4">How ScamShield Works</h2>
            <p className="text-lg text-gray-300">
              Simply enter a URL into our platform, and within seconds, you'll receive a comprehensive report. ScamShield assesses
              multiple factors like domain age, SSL certificate validity, and more to generate an accurate trust score, helping you
              make informed decisions.
            </p>
          </section>

          <section className="cta">
            <h2 className="text-3xl font-semibold text-white mb-4">Start Scanning Today</h2>
            <p className="text-lg text-gray-300">
              Don’t let scams compromise your digital safety. Use ScamShield now and take the first step toward a safer online
              experience. Your protection starts here.
            </p>
          </section>
        </div>

      </main>
    </div>
  );
}
