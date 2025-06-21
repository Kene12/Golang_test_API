import React, { useEffect, useState } from "react";
import { useNavigate, Link } from "react-router-dom";

function ListUsers() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const role = localStorage.getItem("typeUser")?.toLowerCase();
    if (role !== "admin") {
      navigate("/");
      return;
    }

    document.title = "User List";

    fetch("http://localhost:5000/manage/showUser", {
      credentials: "include"
    })
      .then((res) => res.json())
      .then((data) => {
        setUsers(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching users:", err);
        setLoading(false);
      });
  }, [navigate]);

  const handleDelete = async (userId) => {
    if (!window.confirm("คุณแน่ใจหรือไม่ว่าต้องการลบผู้ใช้นี้?")) return;

    try {
      const res = await fetch("http://localhost:5000/manage/deleteUser", {
        method: "DELETE",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ userId }),
      });

      if (res.ok) {
        setUsers(users.filter((user) => user._id !== userId));
      } else {
        const data = await res.json();
        alert("❌ ลบไม่สำเร็จ: " + (data.error || "Unknown error"));
      }
    } catch (err) {
      alert("❌ เกิดข้อผิดพลาด: " + err.message);
    }
  };

  const handleEdit = (userId) => {
    navigate(`/users/edit/${userId}`);
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-md px-8 py-4 flex justify-between items-center">
        <div className="text-xl font-bold text-indigo-600">My App</div>
        <div className="flex space-x-6 text-gray-700">
          <Link to="/" className="hover:text-indigo-600">Home</Link>
          <Link to="/AddProducts" className="hover:text-indigo-600">Add Product</Link>
          <Link to="/products" className="hover:text-indigo-600">Product</Link>
          <button
            onClick={() => {
              localStorage.setItem("auth", "false");
              localStorage.removeItem("typeUser");
              navigate("/");
            }}
            className="hover:text-red-600"
          >
            Logout
          </button>
        </div>
      </nav>

      <div className="p-6">
        <h2 className="text-2xl font-bold mb-4">User List</h2>

        {loading ? (
          <p className="text-gray-500">Loading user data...</p>
        ) : users.length === 0 ? (
          <p className="text-gray-500">No users found</p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {users.map((user) => (
              <div key={user._id} className="bg-white p-4 rounded shadow hover:shadow-md transition-all">
                <p><strong>Username:</strong> {user.username}</p>
                <p><strong>Email:</strong> {user.email}</p>
                <p><strong>Role:</strong> <span className="capitalize">{user.role}</span></p>

                <div className="mt-4 flex space-x-2">
                  <button
                    onClick={() => handleEdit(user._id)}
                    className="bg-yellow-400 hover:bg-yellow-500 text-white px-4 py-1 rounded"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleDelete(user._id)}
                    className="bg-red-500 hover:bg-red-600 text-white px-4 py-1 rounded"
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default ListUsers;