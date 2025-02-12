"use client";
import Api from "@/utils/api";
import { useState } from "react";

export default function Blacklist() {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [loaded, setLoaded] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    const url = e.target.elements.url.value;

    Api.get(`scanner/blacklist/?url=${url}`)
      .then((response) => {
        setResults(response.data);
      })
      .catch((error) => {
        setError("Failed to fetch data");
      });
    setLoaded(true);
  };

  return (
    <div className="grid grid-rows-[20px_1fr_20px] items-center justify-items-center mt-4 p-8 pb-20 gap-16 sm:p-20 bg-gray-900 text-gray-300 font-sans">
      <main className="flex flex-col gap-8 row-start-2 items-center sm:items-start w-full">
        <h1 className="text-4xl font-bold text-center text-blue-500">
          ScamShield Blacklist Database
        </h1>
        <form onSubmit={handleSubmit} className="w-full max-w-lg mx-auto mt-8">
          <div className="mb-6">
            <label
              className="block uppercase tracking-wide text-sm font-bold mb-2 text-gray-300"
              htmlFor="grid-url"
            >
              Domain / URL
            </label>
            <input
              className="appearance-none block w-full bg-gray-800 text-gray-200 border border-gray-700 rounded py-3 px-4 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500"
              id="grid-url"
              type="text"
              name="url"
              placeholder="Enter URL"
            />
          </div>
          <div className="w-full">
            <button
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              type="submit"
            >
              Submit
            </button>
          </div>
        </form>

        {/* Results */}
        {results.length > 0 && (
          <div className="w-full md:w-full px-3 mb-6 md:mb-0">
            <label className="block uppercase tracking-wide text-xs font-bold mb-2 text-gray-300">
              Results
            </label>
            <div className="w-full bg-gray-800 border border-gray-700 rounded py-3 px-4 mb-3 leading-tight">
              <ul className="divide-y divide-gray-700 w-full">
                {results.map((result) => (
                  <li key={result.id} className="py-4 text-gray-300">
                    <div>{result.url}</div>
                    <hr className="my-2" />
                    <div className="flex items-center justify-between">
                      <div>{result.reason}</div>
                      <div>{result.message}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {loaded && results.length === 0 && (
          <div className="w-full md:w-full px-3 mb-6 md:mb-0">
            <label className="block uppercase tracking-wide text-xs font-bold mb-2 text-gray-300">
              Results
            </label>
            <div className="w-full bg-gray-800 border border-gray-700 rounded py-3 px-4 mb-3 leading-tight">
              <div className="text-center text-gray-300">No Blacklist Found</div>
            </div>
          </div>
        )}

        {/* Request Blacklist Removal CTA */}
        <div className="w-full p-6 bg-gray-800 border border-gray-700 rounded-lg shadow-md">
          <a href="#">
            <h5 className="mb-2 text-2xl font-bold text-gray-300">
              Request Blacklist Removal
            </h5>
          </a>
          <p className="mb-3 text-gray-300">
            If you believe your domain has been blacklisted by mistake, you can request removal from the blacklist.
          </p>
          <a
            href="/blacklist/removal"
            className="inline-flex items-center px-3 py-2 text-sm font-medium text-center text-white bg-blue-700 rounded-lg hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300"
          >
            Request Removal
          </a>
        </div>
      </main>
    </div>
  );
}
