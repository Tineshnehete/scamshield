import axios from "axios";

const Api = axios.create({
    baseURL: "http://localhost:8000",
    // WWW-Authenticate: Basic realm="api"
    headers: {
        "Content-Type": "application/json",
        
    },
    });
Api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem("token");
        if (token) {
            config.headers.Authorization = `Token ${token}`; 
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);
export default Api;