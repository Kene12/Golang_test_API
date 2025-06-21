import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

function LoginPage() {
  const [iden, setIden] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const auth = localStorage.getItem("auth");
    document.title = "Login | My Shop";
    if (auth === "true") {
      navigate("/");
    }
  }, [navigate]);

  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      const res = await fetch("http://localhost:5000/auth/login", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ iden, password }),
      });

      const data = await res.json();

      if (res.ok) {
        localStorage.setItem("auth", "true");
        const meRes = await fetch("http://localhost:5000/auth/my", {
          method: "GET",
          credentials: "include",
        });

        const meData = await meRes.json();

        if (meRes.ok) {
          localStorage.setItem("typeUser", meData.role);
          setMessage("✅ Login Success");

          // 🔀 นำทางตาม role
          if (meData.role === "Merchant") {
            navigate("/products");
          } else {
            navigate("/");
          }
        } else {
          setMessage("❌ Failed to get user role: " + meData.error);
        }
      } else {
        setMessage("❌ " + data.error);
      }
    } catch (err) {
      setMessage("❌ Error: " + err.message);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-6">
      
      <form
        onSubmit={handleLogin}
        className="bg-white p-6 rounded-lg shadow-md w-full max-w-md space-y-4"
      >
        <div className="text-left">
            <button
            type="button"
            onClick={() => navigate(-1)}
            className="text-purple-600 hover:text-purple-800 text-lg font-medium transition flex items-center"
            >
            ⬅️ Back
            </button>
        </div>
        <h2 className="text-2xl font-bold text-center">Login</h2>

        <input
          type="text"
          placeholder="Username or Email"
          value={iden}
          onChange={(e) => {
            setIden(e.target.value);
            setMessage("");
          }}
          className="w-full px-4 py-2 border rounded-md"
          required
        />

        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            setMessage("");
          }}
          className="w-full px-4 py-2 border rounded-md"
          required
        />

        {message && (
          <p
            className={`text-center text-sm ${
              message.includes("✅") ? "text-green-600" : "text-red-500"
            }`}
          >
            {message}
          </p>
        )}

        <button
          type="submit"
          className="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700"
        >
          Login
        </button>

        <button
          type="button"
          className="w-full border border-blue-600 text-blue-600 py-2 rounded-md hover:bg-blue-50"
          onClick={() => navigate("/Register")}
        >
          Register
        </button>
      </form>
    </div>
  );
}

export default LoginPage;
