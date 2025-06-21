import React, { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

function EditProduct() {
  const { productId } = useParams();
  const [product, setProduct] = useState(null);
  const [message, setMessage] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    document.title = "Edit Product";
    fetch(`http://localhost:5000/product/product/${productId}`, {
      credentials: "include",
    })
      .then((res) => res.json())
      .then((data) => setProduct(data))
      .catch(() => setMessage("Failed to load product."));
  }, [productId]);

  const handleUpdate = async (e) => {
    e.preventDefault();

    try {
      const res = await fetch("http://localhost:5000/product/editProduct", {
        method: "PATCH",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          productId,
          productName: product.productName,
          description: product.description,
          price: product.price,
          stock: product.stock,
          category: product.category,
        }),
      });

      const data = await res.json();
      if (res.ok) {
        setMessage("✅ Product updated successfully.");
        setTimeout(() => navigate("/products"), 1000);
      } else {
        setMessage("❌ " + data.error);
      }
    } catch (err) {
      setMessage("❌ " + err.message);
    }
  };

  if (!product) return <p className="p-6">Loading product...</p>;

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-6">
      <form onSubmit={handleUpdate} className="bg-white p-6 rounded shadow-md w-full max-w-lg space-y-4">
        <h2 className="text-2xl font-bold text-center">Edit Product</h2>

        <input
          type="text"
          placeholder="Product Name"
          value={product.productName}
          onChange={(e) => setProduct({ ...product, productName: e.target.value })}
          className="w-full px-4 py-2 border rounded"
          required
        />

        <textarea
          placeholder="Description"
          value={product.description}
          onChange={(e) => setProduct({ ...product, description: e.target.value })}
          className="w-full px-4 py-2 border rounded"
        />

        <input
          type="number"
          placeholder="Price"
          value={product.price}
          onChange={(e) => setProduct({ ...product, price: e.target.value })}
          className="w-full px-4 py-2 border rounded"
          required
        />

        <input
          type="number"
          placeholder="Stock"
          value={product.stock}
          onChange={(e) => setProduct({ ...product, stock: e.target.value })}
          className="w-full px-4 py-2 border rounded"
        />

        <input
          type="text"
          placeholder="Category"
          value={product.category}
          onChange={(e) => setProduct({ ...product, category: e.target.value })}
          className="w-full px-4 py-2 border rounded"
        />

        {message && (
          <p className={`text-center text-sm ${message.includes("✅") ? "text-green-600" : "text-red-500"}`}>
            {message}
          </p>
        )}

        <div className="flex justify-between">
          <button
            type="submit"
            className="bg-blue-600 text-white py-2 px-6 rounded hover:bg-blue-700"
          >
            Save Changes
          </button>
          <button
            type="button"
            className="bg-gray-300 text-black py-2 px-6 rounded hover:bg-gray-400"
            onClick={() => navigate("/products")}
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

export default EditProduct;