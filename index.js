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

// Validate critical environment variables
if (!JWT_SECRET) {
  console.error("❌ FATAL: JWT_SECRET missing");
  process.exit(1);
}

if (!adminEmail || !adminPasswordHash) {
  console.error("❌ FATAL: ADMIN credentials missing");
  process.exit(1);
}

app.use(express.json());

// CORS Configuration
const allowedOrigins = [
  'https://www.bbigmart.com',
  'https://bbigmart.com',
  'https://admin.bbigmart.com',
  'http://localhost:4000' // For local testing
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = `CORS policy blocks access from: ${origin}`;
      console.error(msg);
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true, // Important for cookies/sessions
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'auth-token']
}));

// Force HTTPS in production
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
  });
}

// MongoDB Connection with improved retry logic
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log("✅ MongoDB connected");
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err.message);
    setTimeout(connectDB, 5000); // Retry every 5 seconds
  }
};
connectDB();

// Ensure upload directory exists
const uploadDir = path.join(__dirname, 'upload/images');

// Create upload directory if it doesn't exist
try {
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
    console.log(`✅ Created upload directory: ${uploadDir}`);
  }
  
  // Test write permissions
  fs.accessSync(uploadDir, fs.constants.W_OK);
  console.log(`✅ Upload directory is writable: ${uploadDir}`);
} catch (err) {
  console.error(`❌ Upload directory error: ${err.message}`);
  process.exit(1);
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
  bankTransferCode: { type: String, required: false },
  date: {
    type: Date,
    default: Date.now
  }
});

app.get('/favicon.ico', (req, res) => res.status(204));

app.use((err, req, res, next) => {
  console.error('🚨 Error:', err.stack);
  
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  
  res.status(statusCode).json({
    success: false,
    status: statusCode,
    message: message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

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
  if (!req.file) {
    return res.status(400).json({ success: 0, message: "No file uploaded" });
  }
  res.json({
    success: 1,
    image_url: `${getBaseUrl()}/images/${req.file.filename}`
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

// Update product endpoints with fixed image URLs
const getBaseUrl = () => {
  if (process.env.NODE_ENV === 'production') {
    return 'https://backend-repo-op0f.onrender.com';
  }
  return `http://localhost:${PORT}`;
};

app.get('/allproducts', async (_, res) => {
  try {
    const products = await Product.find();
    const baseUrl = getBaseUrl();
    
    const updatedProducts = products.map(p => ({
      ...p._doc,
      image: p.image.startsWith('http') ? p.image : `${baseUrl}${p.image}`
    }));
    
    res.json(updatedProducts);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get('/newcollections', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 16;
  const skip = (page - 1) * limit;
  const baseUrl = getBaseUrl();

  try {
    const products = await Product.find().sort({ date: -1 }).skip(skip).limit(limit);
    const total = await Product.countDocuments();
    
    const updatedProducts = products.map(p => ({
      ...p._doc,
      image: p.image.startsWith('http') ? p.image : `${baseUrl}${p.image}`
    }));
    
    res.json({ products: updatedProducts, total });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get('/popularinwomen', async (_, res) => {
  const baseUrl = getBaseUrl();
  const women = await Product.find({ category: "women" }).limit(4);
  
  const updatedWomen = women.map(p => ({
    ...p._doc,
    image: p.image.startsWith('http') ? p.image : `${baseUrl}${p.image}`
  }));
  
  res.json(updatedWomen);
});

// Fixed admin login with proper validation
app.post('/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        errors: "Email and password are required" 
      });
    }

    // Check email
    if (email !== adminEmail) {
      console.log(`Admin login attempt with wrong email: ${email}`);
      return res.status(401).json({ 
        success: false, 
        errors: "Invalid credentials" 
      });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, adminPasswordHash);
    if (!isMatch) {
      console.log('Admin login attempt with wrong password');
      return res.status(401).json({ 
        success: false, 
        errors: "Invalid credentials" 
      });
    }

    // Generate token
    const token = jwt.sign(
      { 
        user: { 
          email: adminEmail, 
          role: 'admin',
          id: 'admin' // Add a static ID for admin
        } 
      }, 
      JWT_SECRET,
      { expiresIn: '8h' } // Token expiration
    );

    res.json({ 
      success: true, 
      token,
      user: {
        email: adminEmail,
        role: 'admin'
      }
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ 
      success: false, 
      errors: "Server error during login" 
    });
  }
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

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
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
  } catch (err) {
    res.status(500).json({ success: false, errors: err.message });
  }
});

// Cart APIs
app.post('/addtocart', fetchUser, async (req, res) => {
  try {
    const { item } = req.body;
    const user = await User.findById(req.user.id);
    user.cartData[item] = (user.cartData[item] || 0) + 1;
    await user.save();
    res.send("Added");
  } catch (err) {
    console.error('Add to cart error:', err);
    res.status(500).json({ error: 'Failed to add to cart' });
  }
});

app.post('/removefromcart', fetchUser, async (req, res) => {
  try {
    const { item } = req.body;
    const user = await User.findById(req.user.id);
    if (user.cartData[item] > 0) user.cartData[item] -= 1;
    await user.save();
    res.send("Removed");
  } catch (err) {
    console.error('Remove from cart error:', err);
    res.status(500).json({ error: 'Failed to remove from cart' });
  }
});

app.post('/getcart', fetchUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.json(user.cartData);
  } catch (err) {
    console.error('Get cart error:', err);
    res.status(500).json({ error: 'Failed to get cart' });
  }
});

app.post('/clearcart', fetchUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const emptyCart = {};
    for (let i = 0; i <= 300; i++) {
      emptyCart[i] = 0;
    }
    user.cartData = emptyCart;
    await user.save();
    res.send("Cart cleared");
  } catch (err) {
    console.error('Clear cart error:', err);
    res.status(500).json({ error: 'Failed to clear cart' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Base URL: ${getBaseUrl()}`);
});