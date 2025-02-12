"use client"
import Api from "@/utils/api";
import AuthForm from "./auth";

import { useRouter } from "next/navigation";

const BlacklistRemovalForm = () => {
    const router = useRouter();
    const handleSubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        Api.post("/scanner/blacklist/removal-request/", {
            url: form.url.value,
            domain: form.domain.value,
            organization: form.organization.value,
            context: form.context.value,
            reason: form.reason.value
        }).then((response) => {
            if (response.status === 200) {
                alert("Request submitted successfully");
                form.reset();
            } else {
                alert("Request failed");
            }
        }).catch((error) => {
            alert("Request failed");
        });
    }


    return (
        <div>
            <form onSubmit={handleSubmit} className="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4 flex flex-wrap">
     
                <div className="w-full md:w-full px-3 mb-6 md:mb-0">
                    <label className="block uppercase tracking-wide text-gray-700 text-xs font-bold mb-2" htmlFor="grid-url">
                        URL
                    </label>
                    <input className="appearance-none block w-full bg-gray-200 text-gray-700 border border-gray-200 rounded py-3 px-4 mb-3 leading-tight focus:outline-none focus:bg-white" id="grid-url" type="text" name="url" placeholder="Enter URL" />
                </div>
                <div className="w-full md:w-full px-3 mb-6 md:mb-0">
                    <label className="block uppercase tracking-wide text-gray-700 text-xs font-bold mb-2" htmlFor="grid-domain">
                        Main Domain
                    </label>
                    <input className="appearance-none block w-full bg-gray-200 text-gray-700 border border-gray-200 rounded py-3 px-4 mb-3 leading-tight focus:outline-none focus:bg-white" id="grid-domain" type="text" name="domain" placeholder="Enter Domain" />
                </div>
                <div className="w-full md:w-full px-3 mb-6 md:mb-0">
                    <label className="block uppercase tracking-wide text-gray-700 text-xs font-bold mb-2" htmlFor="grid-organization">
                        Organization
                    </label>
                    <input className="appearance-none block w-full bg-gray-200 text-gray-700 border border-gray-200 rounded py-3 px-4 mb-3 leading-tight focus:outline-none focus:bg-white" id="grid-organization" type="text" name="organization" placeholder="Enter Organization" />
                </div>
                <div className="w-full md:w-full px-3 mb-6 md:mb-0">
                    <label className="block uppercase tracking-wide text-gray-700 text-xs font-bold mb-2" htmlFor="grid-context">
                        Context
                    </label>
                    <input className="appearance-none block w-full bg-gray-200 text-gray-700 border border-gray-200 rounded py-3 px-4 mb-3 leading-tight focus:outline-none focus:bg-white" id="grid-context" type="text" name="context" placeholder="Enter Context" />
                </div>
                <div className="w-full md:w-full px-3 mb-6 md:mb-0">
                    <label className="block uppercase tracking-wide text-gray-700 text-xs font-bold mb-2" htmlFor="grid-reason">
                        Reason
                    </label>
                    <input className="appearance-none block w-full bg-gray-200 text-gray-700 border border-gray-200 rounded py-3 px-4 mb-3 leading-tight focus:outline-none focus:bg-white" id="grid-reason" type="text" name="reason" placeholder="Enter Reason" />
                </div>
                <div className="w-full md:w-full px-3 mb-6 md:mb-0">
                    <button className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded" type="submit">
                        Submit
                    </button>

                </div>
            </form>
            {
                    !localStorage.getItem("token") ? <div className="absolute top-0 left-0 w-full h-full bg-gray-900 bg-opacity-50 flex items-center justify-center">
                        <div className="bg-white p-8 rounded shadow-md w-full max-w-md">

                            <AuthForm onSuccess={
                                () => {
                                    router.refresh();
                                }
                            } />
                        </div>
                    </div> : null
                }
        </div>
    );
}
export default BlacklistRemovalForm;