import React, { useEffect } from "react";
import { useNavigate } from "react-router-dom";

function SelectRolePage() {
  const navigate = useNavigate();
  useEffect(() => {
      document.title = "Register | My Shop";
    }, []);
  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-6">
      <div className="bg-white p-6 rounded-lg shadow-md w-full max-w-md space-y-6">
        <div className="text-left">
            <button
            type="button"
            onClick={() => navigate(-1)}
            className="text-purple-600 hover:text-purple-800 text-lg font-medium transition flex items-center"
            >
            ⬅️ Back
            </button>
        </div>

        <h2 className="text-2xl font-bold text-center">Register as</h2>

        <button
            onClick={() => navigate("/register/customer")}
            className="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700"
        >
            Customer
        </button>

        <button
            onClick={() => navigate("/register/merchant")}
            className="w-full bg-green-600 text-white py-2 rounded-md hover:bg-green-700"
        >
            Merchant
        </button>
        </div>
    </div>
  );
}

export default SelectRolePage;
