"use client"
import Api from "@/utils/api";
import { useRouter } from "next/navigation";
import { useState } from "react";

const AuthForm = ({ onSuccess }) => {
    const router = useRouter();

    const handleSubmit = (e) => {
        e.preventDefault();
        if (formMode === "login") {
            const username = e.target.elements.username.value;
            const password = e.target.elements.password.value

            Api.post("api-token-auth/", { username, password })
                .then((response) => {
                    console.log(response);
                    localStorage.setItem("token", response.data.token);

                    router.refresh();
                    onSuccess ? onSuccess() : null;
                })
                .catch((error) => {
                    console.log(error);
                });
        }
        else {
            const username = e.target.elements.username.value;
            const password = e.target.elements.password.value
            const email = e.target.elements.email.value

            Api.post("/scanner/api-auth/signup", { username, password, email })
                .then((response) => {
                    console.log(response);
                    setFormMode("login");
                })
                .catch((error) => {
                    console.log(error);
                });
        }
    }
    const [formMode, setFormMode] = useState("login");
    return (
        <div id="auth" className="flex items-center justify-center bg-gray-900 text-white  p-8">
            {formMode === "login" ? (
                <div className="bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md">
                    <h1 className="text-3xl font-bold mb-6 text-center">Login</h1>
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <input
                            type="text"
                            name="username"
                            placeholder="Username"
                            className="w-full px-4 py-3 bg-gray-700 text-white border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        <input
                            type="password"
                            name="password"
                            placeholder="Password"
                            className="w-full px-4 py-3 bg-gray-700 text-white border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        <button
                            type="submit"
                            className="w-full bg-blue-600 text-white py-3 rounded hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        >
                            Login
                        </button>
                        <div className="text-center text-sm text-gray-400">
                            <a href="#auth" onClick={() => setFormMode("register")}>
                                Don't have an account? Register
                            </a>
                        </div>
                    </form>
                </div>
            ) : (
                <div className="bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md">
                    <h1 className="text-3xl font-bold mb-6 text-center">Register</h1>
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <input
                            type="text"
                            name="username"
                            placeholder="Username"
                            className="w-full px-4 py-3 bg-gray-700 text-white border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        <input
                            type="email"
                            name="email"
                            placeholder="Email"
                            className="w-full px-4 py-3 bg-gray-700 text-white border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        <input
                            type="password"
                            name="password"
                            placeholder="Password"
                            className="w-full px-4 py-3 bg-gray-700 text-white border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        <button
                            type="submit"
                            className="w-full bg-blue-600 text-white py-3 rounded hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        >
                            Register
                        </button>
                        <div className="text-center text-sm text-gray-400">
                            <a href="#auth" onClick={() => setFormMode("login")}>
                                Already have an account? Login
                            </a>
                        </div>
                    </form>
                </div>
            )}
        </div>

    );
}

export default AuthForm;