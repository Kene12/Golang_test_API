import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

function AddProducts() {
  const [productName, setProductName] = useState("");
  const [description, setDescription] = useState("");
  const [price, setPrice] = useState("");
  const [stock, setStock] = useState("");
  const [category, setCategory] = useState("");
  const [message, setMessage] = useState("");
  const [image, setImage] = useState(null);

  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();

    const formData = new FormData();
    formData.append("productName", productName);
    formData.append("description", description);
    formData.append("price", price);
    formData.append("stock", stock);
    formData.append("category", category);
    if (image) {
      formData.append("image", image);
    }

    try {
      const res = await fetch("http://localhost:5000/product/plusProduct", {
        method: "POST",
        credentials: "include",
        body: formData,
      });

      const data = await res.json();
      if (res.ok) {
        setMessage("✅ " + data.message);
        // Reset form
        setProductName("");
        setDescription("");
        setPrice("");
        setStock("");
        setCategory("");
        setImage(null);
      } else {
        setMessage("❌ " + data.error);
      }
    } catch (err) {
      setMessage("❌ " + err.message);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-6">
      <form
        onSubmit={handleSubmit}
        className="bg-white p-6 rounded-lg shadow-md w-full max-w-lg space-y-4"
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
        <h2 className="text-2xl font-bold text-center">Add New Product</h2>

        <input
          type="text"
          placeholder="Product Name"
          value={productName}
          onChange={(e) => setProductName(e.target.value)}
          className="w-full px-4 py-2 border rounded-md"
          required
        />

        <textarea
          placeholder="Description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          className="w-full px-4 py-2 border rounded-md"
        />

        <input
          type="number"
          placeholder="Price"
          value={price}
          onChange={(e) => setPrice(e.target.value)}
          className="w-full px-4 py-2 border rounded-md"
          required
        />

        <input
          type="number"
          placeholder="Stock"
          value={stock}
          onChange={(e) => setStock(e.target.value)}
          className="w-full px-4 py-2 border rounded-md"
        />

        <input
          type="text"
          placeholder="Category"
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="w-full px-4 py-2 border rounded-md"
        />
        <input
          type="file"
          accept="image/*"
          onChange={(e) => setImage(e.target.files[0])}
          className="w-full px-4 py-2 border rounded-md"
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

        <div className="flex justify-between">
          <button
            type="submit"
            className="bg-blue-600 text-white py-2 px-6 rounded-md hover:bg-blue-700"
          >
            Add Product
          </button>

          <button
            type="button"
            className="bg-gray-300 text-black py-2 px-6 rounded-md hover:bg-gray-400"
            onClick={() => navigate(-1)}
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

export default AddProducts;