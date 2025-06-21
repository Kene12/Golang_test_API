import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Products from "./pages/Products";
import Register from "./pages/SelectRolePage";
import Customer from "./pages/customer.js";
import Merchant from "./pages/merchant.js";
import LoginPage from "./pages/loginpage";
import MainPage from "./pages/ProductPage.js";
import AddProducts from "./pages/AddProducts.js";
import UserDetails from "./pages/UserDetails.js";
import Userlist from "./pages/Userlist.js";
import EditProduct from "./pages/editProduct.js";
import ProtectedRoute from "./components/ProtectedLoginRoute";

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<MainPage />} />
        <Route path="/Login" element={<LoginPage />} />
        <Route path="/products" element={
          <ProtectedRoute>
            <Products />
          </ProtectedRoute>
        } />
        <Route path="/Register" element={<Register />} />
        <Route path="/register/customer" element={<Customer />} />
        <Route path="/register/merchant" element={<Merchant />} />
        <Route path="/AddProducts" element={<AddProducts />} />
        <Route path="/UserDetails" element={<UserDetails />} />
        <Route path="/products/EditProduct/:productId" element={<EditProduct />} />
        <Route path="/Userlist" element={<Userlist />} />
      </Routes>
    </Router>
  );
}

export default App;
