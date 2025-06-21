// Register.js
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

function RegisterPage() {
  const [username, setUser] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPass] = useState("");
  const [message, setMessage] = useState("");
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();

    try {
      const res = await fetch("http://localhost:5000/auth/registerMerchant", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, email, password }),
      });

      const data = await res.json();
      if (res.ok) {
        setMessage("✅ Register Success!");
        navigate("/Login");
      } else {
        setMessage("❌ " + data.error);
      }
    } catch (err) {
      setMessage("❌ Error: " + err.message);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-6">
      
      <form onSubmit={handleRegister} className="bg-white p-6 rounded-lg shadow-md w-full max-w-md space-y-4">
      <button
            type="button"
            onClick={() => navigate(-1)}
            className="inline-block text-purple-600 hover:text-purple-800 text-lg font-medium transition"
        >
            ⬅️ Back
        </button>
        <h2 className="text-2xl font-bold text-center">Register</h2>

        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => {
            setUser(e.target.value);
            setMessage("");
          }}
          className="w-full px-4 py-2 border rounded-md"
          required
        />

        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => {
            setEmail(e.target.value);
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
            setPass(e.target.value);
            setMessage("");
          }}
          className="w-full px-4 py-2 border rounded-md"
          required
        />

        <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700">
          Register
        </button>

        {message && <p className="text-center text-sm text-red-500">{message}</p>}
      </form>
    </div>
  );
}

export default RegisterPage;
