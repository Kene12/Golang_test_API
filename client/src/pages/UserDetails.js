import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

function UserDetails() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await fetch("http://localhost:5000/auth/my", {
          credentials: "include",
        });

        const data = await res.json();
        if (res.ok) {
          setUser(data);
        } else {
          console.error("Cannot fetch user:", data.error);
        }
      } catch (err) {
        console.error("Error fetching user:", err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, []);

  if (loading) return <p className="p-4">Loading...</p>;
  if (!user) return <p className="p-4 text-red-600">No user data available</p>;

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-6">
      <div className="bg-white p-6 rounded-lg shadow-md w-full max-w-md space-y-4">
        <div className="text-left">
            <button
            type="button"
            onClick={() => navigate(-1)}
            className="text-purple-600 hover:text-purple-800 text-lg font-medium transition flex items-center"
            >
            ⬅️ Back
            </button>
        </div>
        <h2 className="text-2xl font-bold text-center">User Details</h2>

        <div className="text-gray-800">
          <p><strong>Username:</strong> {user.username}</p>
          <p><strong>Email:</strong> {user.email}</p>
          <p><strong>Role:</strong> <span className="capitalize">{user.role}</span></p>
        </div>

        <div className="flex justify-between pt-4">
          <button
            onClick={() => navigate("/edit-user")}
            className="bg-yellow-500 hover:bg-yellow-600 text-white px-4 py-2 rounded"
          >
            Edit
          </button>

          <button
            onClick={() => navigate("/change-password")}
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
          >
            Change Password
          </button>
        </div>
      </div>
    </div>
  );
}

export default UserDetails;