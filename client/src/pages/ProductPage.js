import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

function ProductPage() {
  const [cartOpen, setCartOpen] = useState(false);
  const [cartItems, setCartItems] = useState([]);
  const [products, setProducts] = useState([]);
  const [cartCount, setCartCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [typeUser, setTypeUser] = useState("");

  const navigate = useNavigate();
  const [visibleCount, setVisibleCount] = useState(9);

  useEffect(() => {
    const auth = localStorage.getItem("auth");
    const role = localStorage.getItem("typeUser");
    document.title = "My Shop";

    setIsLoggedIn(auth === "true");
    setTypeUser(role?.toLowerCase());

    const fetchProducts = async () => {
      try {
        const res = await fetch("http://localhost:5000/product/products", {
          credentials: "include",
        });
        const data = await res.json();

        if (res.ok) {
          setProducts(data);
        } else {
          setError(data.error || "Failed to fetch products");
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchProducts();
    fetchCartItems();
  }, []);

  

  const fetchCartItems = async () => {
    try {
      const res = await fetch("http://localhost:5000/product/my", {
        credentials: "include",
      });
      const data = await res.json();
      if (res.ok) {
        setCartItems(data);
        setCartCount(data.reduce((sum, item) => sum + item.quantity, 0));
      } else {
        console.error(data.error);
      }
    } catch (err) {
      console.error("Error loading cart:", err.message);
    }
  };

  const toggleCart = async () => {
    if (!cartOpen) {
      await fetchCartItems();
    }
    setCartOpen(!cartOpen);
  };

  const handleBuy = async (productId) => {
    try {
      const res = await fetch("http://localhost:5000/product/add", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({ productId, quantity: 1 }),
      });

      if (res.ok) {
        setCartCount((prev) => prev + 1);
        await fetchCartItems();
      } else {
        navigate("/login");
      }
    } catch (err) {
      alert("❌ Error adding to cart: " + err.message);
    }
  };

  const handleIncreaseQuantity = async (productId) => {
    try {
      const res = await fetch("http://localhost:5000/product/add", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ productId, quantity: 1 }),
      });
      if (res.ok) {
        await fetchCartItems();
      }
    } catch (err) {
      alert("❌ Error: " + err.message);
    }
  };

  const handleDecreaseQuantity = async (productId) => {
    try {
      const res = await fetch("http://localhost:5000/product/remove", {
        method: "DELETE",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ productId }),
      });
      if (res.ok) {
        await fetchCartItems();
      }
    } catch (err) {
      alert("❌ Error: " + err.message);
    }
  };

  const handleRemoveFromCart = async (productId) => {
    try {
      const res = await fetch("http://localhost:5000/product/removeAll", {
        method: "DELETE",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ productId }),
      });

      if (res.ok) {
        setCartCount((prev) => prev - 1);
        await fetchCartItems();
      } else {
        const data = await res.json();
        alert("❌ " + (data.error || "Failed to remove item"));
      }
    } catch (err) {
      alert("❌ Error: " + err.message);
    }
};

  const handleLogout = async () => {
    try {
      const res = await fetch("http://localhost:5000/auth/logout", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
      });

      if (res.ok) {
        localStorage.removeItem("auth");
        localStorage.removeItem("typeUser");
        setIsLoggedIn(false);
        setTypeUser("");
        navigate("/");
        window.location.reload();
      } else {
        console.error("Logout failed");
      }
    } catch (err) {
      console.error("Error logging out:", err);
    }
  };

  const groupedCart = cartItems.reduce((acc, item) => {
    const id = item.productId._id || item.productId;
    const name = item.productId.productName || "Unknown";
    const price = item.productId.price || 0;

    if (!acc[id]) {
      acc[id] = { name, price, quantity: 0 };
    }

    acc[id].quantity += item.quantity;
    return acc;
  }, {});

  return (
    <div className="min-h-screen bg-gray-100 p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">🛍️ Products</h1>

        <div className="flex items-center space-x-4">
          <button
            onClick={() => navigate("/")}
            className="text-blue-600 hover:text-blue-800 font-medium"
          >
            Home
          </button>

          {!isLoggedIn ? (
            <>
              <button
                onClick={() => navigate("/login")}
                className="text-blue-600 hover:text-blue-800 font-medium"
              >
                Login
              </button>
              <button
                onClick={() => navigate("/register")}
                className="text-blue-600 hover:text-blue-800 font-medium"
              >
                Register
              </button>
            </>
          ) : (
            <>
              {(typeUser === "merchant" || typeUser === "admin") && (
                <button
                  onClick={() => navigate("/products")}
                  className="text-blue-600 hover:text-blue-800 font-medium"
                >
                  Manage Products
                </button>
              )}
              {typeUser === "admin" ? (
                <button
                  onClick={() => navigate("/Userlist")}
                  className="text-blue-600 hover:text-blue-800 font-medium"
                >
                  List User
                </button>
              ) : (
                <button
                  onClick={() => navigate("/UserDetails")}
                  className="text-blue-600 hover:text-blue-800 font-medium"
                >
                  User
                </button>
              )}
              <button
                onClick={handleLogout}
                className="text-red-600 hover:text-red-800 font-medium"
              >
                Logout
              </button>
            </>
          )}

          <div className="relative">
            <button onClick={toggleCart}>
              <span className="text-2xl">🛒</span>
              {cartCount > 0 && (
                <span className="absolute -top-2 -right-2 bg-red-600 text-white text-xs w-5 h-5 flex items-center justify-center rounded-full">
                  {cartCount}
                </span>
              )}
            </button>
            {cartOpen && (
              <div className="absolute right-0 mt-2 w-64 bg-white border shadow-lg rounded-lg z-10 p-4">
                <h3 className="font-bold mb-2">Cart</h3>
                {Object.keys(groupedCart).length === 0 ? (
                  <p className="text-gray-500">Your cart is empty.</p>
                ) : (
                  <ul className="space-y-2">
                    {Object.entries(groupedCart).map(([id, item]) => (
                      <li key={id} className="text-sm flex justify-between items-center">
                        <div className="flex flex-col">
                          <span className="font-medium">{item.name}</span>
                          <span className="text-gray-500">฿{item.price * item.quantity}</span>
                          <div className="flex items-center space-x-2 mt-1">
                            <button
                              onClick={() => handleDecreaseQuantity(id)}
                              className="bg-gray-300 hover:bg-gray-400 px-2 rounded"
                            >
                              −
                            </button>
                            <span>{item.quantity}</span>
                            <button
                              onClick={() => handleIncreaseQuantity(id)}
                              className="bg-gray-300 hover:bg-gray-400 px-2 rounded"
                            >
                              +
                            </button>
                            <button
                              onClick={() => handleRemoveFromCart(id)}
                              className="bg-red-500 hover:bg-red-600 text-white px-2 py-1 rounded text-xs ml-auto"
                            >
                              Delete
                            </button>
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
      
      {loading ? (
        <p>Loading...</p>
      ) : error ? (
        <p className="text-red-600">{"Connect Server"}</p>
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
            {products.slice(0, visibleCount).map((product) => (
              <div
                key={product._id}
                className="bg-white rounded-xl shadow-md overflow-hidden hover:shadow-lg transition-all duration-300"
              >
                {product.img?.data ? (
                  <img
                    src={`data:${product.img.contentType};base64,${btoa(
                      String.fromCharCode(...new Uint8Array(product.img.data.data))
                    )}`}
                    alt={product.productName}
                    className="w-full h-60 object-cover"
                  />
                ) : (
                  <div className="w-full h-60 bg-gray-200 flex items-center justify-center text-gray-500">
                    No Image
                  </div>
                )}

                <div className="p-4 space-y-2">
                  <div className="flex justify-between items-center">
                    <h3 className="text-lg font-bold">{product.productName}</h3>
                    <span className="text-blue-600 font-semibold">฿{product.price}</span>
                  </div>
                  <p className="text-sm text-gray-500">Category: {product.category || "N/A"}</p>
                  <button
                    onClick={() => handleBuy(product._id)}
                    className="w-full mt-2 bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 transition"
                  >
                    Buy
                  </button>
                </div>
              </div>
            ))}
          </div>
          {visibleCount < products.length && (
            <div className="text-center mt-6">
              <button
                onClick={() => setVisibleCount(visibleCount + 10)}
                className="bg-gray-800 text-white px-4 py-2 rounded-md hover:bg-gray-900 transition"
              >
                Load more
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default ProductPage;