import Api from "@/utils/api";
import AuthForm from "./auth";
import { useRouter } from "next/navigation";

const ReportUrlForm = ({url}) => {
    const router = useRouter();
    const handleSubmit = (e) => {
        e.preventDefault(); 
        const reason = e.target.elements.reason.value;
        const comment = e.target.elements.comment.value;

        Api.post("scanner/blacklist/add/", { url, reason: `${reason}` , message: `${comment}` })
            .then((response) => {
                alert("Report submitted successfully");
            })
            .catch((error) => {
                alert("Report submission failed");
            });
    }

    return (
        <>
            <div >
                <h1 className="text-2xl font-bold mb-6 text-center">Report URL</h1>
            </div>
            <div className="w-full relative">
                <form onSubmit={handleSubmit} className="w-full max-w-lg mx-auto mt-8">
                    <div className="flex flex-wrap -mx-3 mb-6">
                        <div className="w-full md:w-full px-3 mb-6 md:mb-0">
                            <label className="block uppercase tracking-wide text-xs font-bold mb-2" htmlFor="grid-url">
                                URL
                            </label>
                            <output className="appearance-none block w-full bg-gray-200 text-gray-700 border border-gray-200 rounded py-3 px-4 mb-3 leading-tight focus:outline-none focus:bg-white" id="grid-url"   name="url" placeholder="Enter URL" >
                                {url}
                            </output>

                        </div>
                        {/* reason */}

                        <div className="w-full md:w-full px-3 mb-6 md:mb-0">
                            <label className="block uppercase tracking-wide text-xs font-bold mb-2" htmlFor="grid-reason">
                                Reason
                            </label>
                            <div className="relative">
                                <select className="block appearance-none w-full bg-gray-200 border border-gray-200 text-gray-700 py-3 px-4 pr-8 rounded leading-tight focus:outline-none focus:bg-white focus:border-gray-500" name="reason" id="grid-reason">
                                    <option value={"phishing"}>Phishing</option>
                                    <option value={"malware"}>Malware</option>
                                    <option value={"spam"}>Spam</option>
                                    <option value={"other"}>Other</option>
                                </select>
                            </div>
                        </div>

                        <div className="w-full md:w-full px-3 mb-6 md:mb-0">
                            <label className="block uppercase tracking-wide  text-xs font-bold mb-2" htmlFor="grid-comment">
                                Comment
                            </label>
                            <textarea className="appearance-none block w-full bg-gray-200 text-gray-700 border border-gray-200 rounded py-3 px-4 mb-3 leading-tight focus:outline-none focus:bg-white" name="comment" id="grid-comment" type="text" placeholder="Enter Comment" />
                        </div>

                        <div className="w-full md:w-full px-3 mb-6 md:mb-0">
                            <button className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded" type="submit">
                                Submit
                            </button>

                        </div>
                    </div>
                </form>

                {/* create overlay id loggedinlocalstorage var not there */}

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


            </div></>
    )
}

export default ReportUrlForm;