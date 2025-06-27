import fs from 'fs';
import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
const adminEmail = process.env.ADMIN_EMAIL;
const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;


app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  retryWrites: true,
  w: 'majority'
}).then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err);
    // Retry after 5 seconds
    setTimeout(() => mongoose.connect(process.env.MONGO_URI), 5000);
  });

const uploadDir = path.join(__dirname, 'upload/images');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Models
const Product = mongoose.model("Product", {
  id: { type: Number, required: true },
  name: { type: String, required: true },
  image: { type: String, required: true },
  category: { type: String, required: true },
  new_price: { type: Number, required: true },
  old_price: { type: Number, required: true },
  description: { type: String, required: false },
  date: { type: Date, default: Date.now },
  available: { type: Boolean, default: true },
});

const User = mongoose.model("User", {
  name: String,
  email: { type: String, unique: true },
  password: String,
  cartData: Object,
  date: { type: Date, default: Date.now }
});

// Middleware to verify JWT
const fetchUser = async (req, res, next) => {
  const token = req.header('auth-token');
  if (!token) return res.status(401).json({ errors: "Auth token missing" });

  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data.user;
    next();
  } catch {
    return res.status(401).json({ errors: "Invalid token" });
  }
};

// Order Model
const Order = mongoose.model("Order", {
  customer: {
    name: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String },
    address: { type: String, required: true }
  },
  products: [{
    id: { type: Number, required: true },
    name: { type: String, required: true },
    price: { type: Number, required: true },
    quantity: { type: Number, required: true },
    image: { type: String, required: true }
  }],
  subtotal: { type: Number, required: true },
  shippingFee: { type: Number, required: true },
  totalAmount: { type: Number, required: true },
  status: {
    type: String,
    enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled'],
    default: 'pending'
  },
  paymentMethod: {
    type: String,
    enum: ['cash', 'card', 'bank'],
    default: 'cash'
  },
  bankTransferCode: { type: String, required: false }, // Added bank transfer code
  date: {
    type: Date,
    default: Date.now
  }
});

app.use(cors({
  origin: '*', // or specific domain like 'https://admin.bbigmart.com'
  methods: ['GET', 'POST', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'auth-token']
}));

app.get('/favicon.ico', (req, res) => res.status(204));

// Create Order
app.post('/api/orders', async (req, res) => {
  try {
    // Validate required fields
    if (!req.body.customer?.name || !req.body.customer?.phone || !req.body.customer?.address) {
      return res.status(400).json({ error: 'Нэр, утасны дугаар, хаяг заавал бөглөнө үү' });
    }

    if (!req.body.products || req.body.products.length === 0) {
      return res.status(400).json({ error: 'Захиалганд бүтээгдэхүүн оруулаагүй байна' });
    }

    const order = new Order(req.body);
    await order.save();

    res.status(201).json(order);
  } catch (err) {
    console.error('Order creation error:', err);
    res.status(400).json({ error: err.message });
  }
});

// Get All Orders
app.get('/api/orders', async (req, res) => {
  try {
    const { status, sort = '-date' } = req.query;

    const query = {};
    if (status && status !== 'all') {
      query.status = status;
    }

    const orders = await Order.find(query).sort(sort);

    res.json({
      orders,
      total: orders.length
    });
  } catch (err) {
    console.error('Error fetching orders:', err);
    res.status(500).json({ error: 'Захиалгыг авах үед алдаа гарлаа' });
  }
});

// Get Single Order
app.get('/api/orders/:id', async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).json({ error: 'Захиалга олдсонгүй' });
    }
    res.json(order);
  } catch (err) {
    console.error('Error fetching order:', err);
    res.status(500).json({ error: 'Захиалгыг авах үед алдаа гарлаа' });
  }
});

// Update Order Status
app.patch('/api/orders/:id', async (req, res) => {
  try {
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ error: 'Статус оруулаагүй байна' });
    }

    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );

    if (!order) {
      return res.status(404).json({ error: 'Захиалга олдсонгүй' });
    }

    res.json(order);
  } catch (err) {
    console.error('Error updating order:', err);
    res.status(400).json({ error: err.message });
  }
});

// Delete Order (Admin only)
app.delete('/api/orders/:id', async (req, res) => {
  try {
    const order = await Order.findByIdAndDelete(req.params.id);
    if (!order) {
      return res.status(404).json({ error: 'Захиалга олдсонгүй' });
    }
    res.json({ message: 'Захиалга устгагдлаа' });
  } catch (err) {
    console.error('Error deleting order:', err);
    res.status(500).json({ error: 'Захиалгыг устгах үед алдаа гарлаа' });
  }
});

// File upload setup
const storage = multer.diskStorage({
  destination: './upload/images',
  filename: (req, file, cb) => {
    cb(null, `${file.fieldname}_${Date.now()}${path.extname(file.originalname)}`);
  }
});
const upload = multer({ storage });
app.use('/images', express.static('upload/images'));

// Routes
app.get("/", (req, res) => res.send("✅ Express server running"));

app.post("/upload", upload.single('product'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: 0, message: "No file uploaded" });
  
  // Use environment variable for base URL
  const baseUrl = process.env.RENDER_EXTERNAL_URL || `https://${process.env.RENDER_INSTANCE_NAME}.onrender.com`;
  
  res.json({
    success: 1,
    image_url: `${baseUrl}/images/${req.file.filename}`
  });
});

// Product APIs
app.post('/addproduct', async (req, res) => {
  try {
    const products = await Product.find().sort({ id: -1 }).limit(1);
    const id = products.length ? products[0].id + 1 : 1;

    const product = new Product({ ...req.body, id });
    await product.save();
    res.json({ success: true, name: req.body.name });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/removeproduct', async (req, res) => {
  try {
    await Product.findOneAndDelete({ id: req.body.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.delete('/api/orders/:id', async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).json({ error: 'Захиалга олдсонгүй' });
    }
    
    // Only allow deletion of delivered orders
    if (order.status !== 'delivered') {
      return res.status(400).json({ 
        error: 'Зөвхөн хүргэгдсэн захиалгыг устгах боломжтой' 
      });
    }

    await Order.findByIdAndDelete(req.params.id);
    res.json({ message: 'Захиалга амжилттай устгагдлаа' });
  } catch (err) {
    console.error('Error deleting order:', err);
    res.status(500).json({ error: 'Захиалгыг устгах үед алдаа гарлаа' });
  }
});

app.post('/clearcart', fetchUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    // Create empty cart
    const emptyCart = {};
    for (let i = 0; i <= 300; i++) {
      emptyCart[i] = 0;
    }

    user.cartData = emptyCart;
    await user.save();
    res.send("Cart cleared");
  } catch (err) {
    console.error('Error clearing cart:', err);
    res.status(500).json({ error: 'Failed to clear cart' });
  }
});

// Update product endpoints to use absolute URLs
app.get('/allproducts', async (_, res) => {
  const products = await Product.find();
  const baseUrl = process.env.RENDER_EXTERNAL_URL;
  
  const updatedProducts = products.map(p => ({
    ...p._doc,
    image: p.image.includes('http') ? p.image : `${baseUrl}${p.image}`
  }));
  
  res.json(updatedProducts);
});

app.get('/newcollections', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 16;
  const skip = (page - 1) * limit;

  try {
    const products = await Product.find().sort({ date: -1 }).skip(skip).limit(limit);
    const total = await Product.countDocuments();
    res.json({ products, total });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


app.get('/popularinwomen', async (_, res) => {
  const women = await Product.find({ category: "women" }).limit(4);
  res.json(women);
});

// User Signup/Login
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ success: false, errors: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const cart = Array.from({ length: 300 }, (_, i) => i).reduce((acc, id) => ({ ...acc, [id]: 0 }), {});

    const user = new User({ name: username, email, password: hashedPassword, cartData: cart });
    await user.save();

    const token = jwt.sign({ user: { id: user._id } }, JWT_SECRET);
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, errors: err.message });
  }
});

app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;
  
  // Check email
  if (email !== process.env.ADMIN_EMAIL) {
    return res.status(401).json({ success: false, errors: "Invalid admin credentials" });
  }

  // Check password against hashed version
  const isMatch = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH); // Fixed env variable
  if (!isMatch) {
    return res.status(401).json({ success: false, errors: "Invalid admin credentials" });
  }

  // Generate token
  const token = jwt.sign({ user: { email, role: 'admin' } }, process.env.JWT_SECRET);
  res.json({ success: true, token });
});
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(401).json({ success: false, errors: "User not found" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ success: false, errors: "Incorrect password" });
  }

  const token = jwt.sign({ user: { id: user._id } }, JWT_SECRET);
  res.json({ success: true, token });
});

// Cart APIs
app.post('/addtocart', fetchUser, async (req, res) => {
  const { item } = req.body;
  const user = await User.findById(req.user.id);
  user.cartData[item] = (user.cartData[item] || 0) + 1;
  await user.save();
  res.send("Added");
});

app.post('/removefromcart', fetchUser, async (req, res) => {
  const { item } = req.body;
  const user = await User.findById(req.user.id);
  if (user.cartData[item] > 0) user.cartData[item] -= 1;
  await user.save();
  res.send("Removed");
});

app.post('/getcart', fetchUser, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.json(user.cartData);
});


// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});