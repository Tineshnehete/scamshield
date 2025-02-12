import BlacklistRemovalForm from "@/components/blacklistremoval";

const BlacklistRemovalPage = () => {
  return (
    <div className="grid grid-rows-[20px_1fr_20px] items-center justify-items-center min-h-screen p-8 pb-20 gap-16 sm:p-20 font-[family-name:var(--font-geist-sans)] bg-gray-900 text-gray-300">
      <main className="flex flex-col gap-8 row-start-2 items-center sm:items-start w-full">
        <h1 className="text-4xl font-bold text-center text-blue-500 mb-6">
          Blacklist Removal
        </h1>
        <p className="text-lg text-center sm:text-left mb-8">
          If you believe your domain has been blacklisted by mistake, you can
          request removal by filling out the form below.
        </p>
        <div className="w-full max-w-xl">
          <BlacklistRemovalForm />
        </div>
      </main>
    </div>
  );
};

export default BlacklistRemovalPage;
