import Api from "./api";

const Scanner = {
    scan: async (url) => {
        const response = await Api.post("/scanner/scan/", { url });
        return response.data;
    },

};

export default Scanner;