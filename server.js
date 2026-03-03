require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const mongoose = require('mongoose');
const Order = require('./models/Order');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

/* ===== ADMIN CREDENTIALS (override via env vars) ===== */
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'ganesh@2025';

/* ===== MONGODB SETUP ===== */
if (!process.env.MONGODB_URI) {
  console.error('❌ MONGODB_URI is missing from environment variables!');
}

let isConnected = false;
const connectDB = async () => {
  if (isConnected) return;
  try {
    const db = await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    isConnected = db.connections[0].readyState === 1;
    console.log('✅ Connected to MongoDB Atlas');
  } catch (err) {
    console.error('❌ MongoDB Connection Error:', err.message);
    throw err;
  }
};

// Start connection but don't block server start
connectDB().catch(() => { });

/* ===== PENDING PAYMENTS STORE (in-memory, expires after 30 min) ===== */
const pendingPayments = new Map();
const PAYMENT_EXPIRY_MS = 30 * 60 * 1000;

/* ===== MIDDLEWARE ===== */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/* ===== SESSION MANAGEMENT (In-memory) ===== */
const sessions = new Map();
function createSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username, createdAt: Date.now() });
  return token;
}
function validateSession(token) {
  if (!token || !sessions.has(token)) return false;
  const session = sessions.get(token);
  // Session expires after 24 hours
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    sessions.delete(token);
    return false;
  }
  return true;
}

/* Auth middleware for admin routes */
function requireAuth(req, res, next) {
  const token = req.cookies?.admin_token ||
    (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
  if (!validateSession(token)) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Unauthorized. Please login at /admin' });
    }
    return res.redirect('/admin');
  }
  next();
}

/* Block direct access to sensitive files */
app.get(['/orders.db', '/server.js', '/package.json', '/package-lock.json', '/.env'], (req, res) => {
  res.status(403).json({ error: 'Access denied' });
});

/* Health check — tests if serverless function + DB are working */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', mongodb: mongoose.connection.readyState === 1, time: new Date().toISOString() });
});

/* ===== STATIC FILES (serve the existing frontend) ===== */
app.use(express.static(__dirname, {
  index: 'index.html',
  extensions: ['html']
}));

/* ===== ORDER API (COD orders only — UPI orders go through /api/payment/verify) ===== */
app.post('/api/orders', async (req, res) => {
  try {
    await connectDB();
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        error: 'Database not connected',
        details: 'The site is having trouble connecting to the cloud database. Please ensure MONGODB_URI is correct and your IP is whitelisted in MongoDB Atlas Network Access.'
      });
    }
    if (!req.body) {
      console.error('❌ COD Error: req.body is undefined');
      return res.status(400).json({ error: 'Payload missing', details: 'The server did not receive any order data.' });
    }
    const body = req.body;

    /* Only COD orders are allowed through this endpoint */
    if (!body.paymentMethod || body.paymentMethod !== 'cod') {
      return res.status(403).json({ error: 'UPI orders must go through payment verification. Use /api/payment/initiate first.' });
    }

    if (!body.orderNo || typeof body.orderNo !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid orderNo' });
    }
    if (!body.name || !body.phone || !body.address) {
      return res.status(400).json({ error: 'Name, phone, and address are required' });
    }

    /* Check for duplicates */
    const existing = await Order.findOne({ order_id: body.orderNo });
    if (existing) {
      return res.status(409).json({ error: 'Order already exists', orderId: body.orderNo });
    }

    /* Parse items */
    let itemNames = '', quantities = '', prices = '';
    if (Array.isArray(body.itemsDetailed) && body.itemsDetailed.length > 0) {
      itemNames = body.itemsDetailed.map(i => i.name).join(' | ');
      quantities = body.itemsDetailed.map(i => String(i.qty)).join(' | ');
      prices = body.itemsDetailed.map(i => `₹${i.price} × ${i.qty} = ₹${i.lineTotal}`).join(' | ');
    } else if (Array.isArray(body.items)) {
      itemNames = body.items.join(' | ');
      quantities = body.items.map(i => {
        const match = i.match(/× (\d+)/);
        return match ? match[1] : '1';
      }).join(' | ');
    }

    const orderData = {
      order_id: String(body.orderNo).trim(),
      order_date: body.timestamp || new Date().toISOString(),
      customer_name: String(body.name || '').trim(),
      customer_phone: String(body.phone || '').trim(),
      delivery_address: String(body.address || '').trim(),
      distance_km: Number(body.distance) || 0,
      items_list: itemNames,
      quantities: quantities,
      item_prices: prices,
      subtotal: Number(body.subtotal) || 0,
      delivery_charges: Number(body.delivery) || 0,
      total_amount: Number(body.total) || 0,
      payment_method: 'COD',
      upi_id: '',
      payment_status: 'COD - Pay on Delivery',
      transaction_id: '',
      customer_lat: body.location?.lat ?? null,
      customer_lon: body.location?.lon ?? null,
      map_link: String(body.mapLink || '').trim(),
      order_source: 'WhatsApp'
    };

    await Order.create(orderData);

    console.log(`✅ COD Order ${orderData.order_id} stored in MongoDB.`);
    res.status(201).json({
      success: true,
      message: 'COD order stored successfully',
      orderId: orderData.order_id
    });

  } catch (err) {
    console.error('❌ COD order error:', err);
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Duplicate order', message: 'Order ID or Transaction already exists' });
    }
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

/* ===== PAYMENT INITIATION ===== */
app.post('/api/payment/initiate', async (req, res) => {
  try {
    await connectDB();
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        error: 'Database not connected',
        details: 'The site is having trouble connecting to the cloud database.'
      });
    }
    if (!req.body) {
      console.error('❌ UPI Init Error: req.body is undefined');
      return res.status(400).json({ error: 'Payload missing', details: 'The server did not receive any order data.' });
    }
    const body = req.body;

    /* Validate cart */
    if (!Array.isArray(body.items) || body.items.length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }
    if (!body.name || !body.phone || !body.address) {
      return res.status(400).json({ error: 'Name, phone, and address are required' });
    }

    const total = Number(body.total) || 0;
    if (total <= 0) {
      return res.status(400).json({ error: 'Invalid order total' });
    }

    /* Generate payment token and order number */
    const paymentToken = uuidv4();
    const orderNo = 'GFJ-' + Date.now().toString(36).toUpperCase().slice(-6);

    /* Store pending payment (NOT in DB) */
    pendingPayments.set(paymentToken, {
      orderNo,
      name: String(body.name).trim(),
      phone: String(body.phone).trim(),
      address: String(body.address).trim(),
      distance: Number(body.distance) || 0,
      items: body.items,
      itemsDetailed: body.itemsDetailed || [],
      subtotal: Number(body.subtotal) || 0,
      delivery: Number(body.delivery) || 0,
      total: total,
      upiId: String(body.upiId || '').trim(),
      location: body.location || null,
      mapLink: String(body.mapLink || '').trim(),
      createdAt: Date.now(),
      verified: false
    });

    console.log(`⏳ Payment initiated for ${orderNo} — token: ${paymentToken.slice(0, 8)}...`);
    res.json({ success: true, paymentToken, orderNo, amount: total });

  } catch (err) {
    console.error('❌ Payment initiation error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ===== PAYMENT VERIFICATION ===== */
app.post('/api/payment/verify', async (req, res) => {
  try {
    await connectDB();
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        error: 'Database not connected',
        details: 'Check your MONGODB_URI/Network settings.'
      });
    }
    const { paymentToken, transactionId } = req.body;

    /* Validate inputs */
    if (!paymentToken || typeof paymentToken !== 'string') {
      return res.status(400).json({ error: 'Missing payment token' });
    }
    if (!transactionId || typeof transactionId !== 'string' || transactionId.trim().length < 3) {
      return res.status(400).json({ error: 'Please enter a valid UPI transaction reference ID (min 3 characters)' });
    }

    const txnId = transactionId.trim();

    /* Check pending payment exists */
    const pending = pendingPayments.get(paymentToken);
    if (!pending) {
      return res.status(404).json({ error: 'Payment session not found or expired. Please try again.' });
    }

    /* Check not already verified */
    if (pending.verified) {
      return res.status(409).json({ error: 'This payment has already been verified.' });
    }

    /* Check expiry */
    if (Date.now() - pending.createdAt > PAYMENT_EXPIRY_MS) {
      pendingPayments.delete(paymentToken);
      return res.status(410).json({ error: 'Payment session expired. Please initiate a new order.' });
    }

    /* Check for duplicate transaction ID */
    const dupCheck = await Order.findOne({ transaction_id: txnId });
    if (dupCheck) {
      return res.status(409).json({ error: 'This transaction ID has already been used for another order.' });
    }

    /* === PAYMENT VERIFIED — Now create the order === */
    pending.verified = true;

    /* Parse items */
    let itemNames = '', quantities = '', prices = '';
    if (Array.isArray(pending.itemsDetailed) && pending.itemsDetailed.length > 0) {
      itemNames = pending.itemsDetailed.map(i => i.name).join(' | ');
      quantities = pending.itemsDetailed.map(i => String(i.qty)).join(' | ');
      prices = pending.itemsDetailed.map(i => `₹${i.price} × ${i.qty} = ₹${i.lineTotal}`).join(' | ');
    } else if (Array.isArray(pending.items)) {
      itemNames = pending.items.join(' | ');
      quantities = pending.items.map(i => {
        const match = i.match(/× (\d+)/);
        return match ? match[1] : '1';
      }).join(' | ');
    }

    const orderData = {
      order_id: pending.orderNo,
      order_date: new Date().toISOString(),
      customer_name: pending.name,
      customer_phone: pending.phone,
      delivery_address: pending.address,
      distance_km: pending.distance,
      items_list: itemNames,
      quantities: quantities,
      item_prices: prices,
      subtotal: pending.subtotal,
      delivery_charges: pending.delivery,
      total_amount: pending.total,
      payment_method: 'UPI',
      upi_id: pending.upiId,
      payment_status: 'Paid',
      transaction_id: txnId,
      customer_lat: pending.location?.lat ?? null,
      customer_lon: pending.location?.lon ?? null,
      map_link: pending.mapLink,
      order_source: 'WhatsApp'
    };

    await Order.create(orderData);

    console.log(`✅ UPI Order ${orderData.order_id} verified & stored in MongoDB.`);
    res.status(201).json({
      success: true,
      message: 'Payment verified — order confirmed!',
      orderId: orderData.order_id,
      transactionId: txnId,
      total: orderData.total_amount,
      orderData: {
        name: orderData.customer_name,
        phone: orderData.customer_phone,
        address: orderData.delivery_address,
        items: pending.items,
        subtotal: orderData.subtotal,
        delivery: orderData.delivery_charges,
        total: orderData.total_amount,
        mapLink: orderData.map_link
      }
    });

  } catch (err) {
    console.error('❌ Payment verification error:', err.message);
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Duplicate order detected.' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ===== ADMIN ROUTES ===== */

/* Admin page */
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

/* Admin login API */
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  if (username !== ADMIN_USER || password !== ADMIN_PASS) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = createSession(username);
  res.cookie('admin_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000
  });
  res.json({ success: true, token });
});

/* Admin logout */
app.post('/admin/logout', (req, res) => {
  const token = req.cookies?.admin_token;
  if (token) sessions.delete(token);
  res.clearCookie('admin_token');
  res.json({ success: true });
});

/* Get all orders (admin only) */
app.get('/api/admin/orders', requireAuth, async (req, res) => {
  try {
    const orders = await Order.find().sort({ created_at: -1 });
    res.json({ success: true, count: orders.length, orders });
  } catch (err) {
    console.error('❌ Fetch orders error:', err.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

/* Export orders as CSV (admin only) */
app.get('/api/admin/export/csv', requireAuth, async (req, res) => {
  try {
    const orders = await Order.find().sort({ created_at: -1 });

    const headers = [
      'Order ID', 'Date & Time', 'Customer Name', 'Phone Number',
      'Delivery Address', 'Distance (km)', 'Items', 'Quantities',
      'Item Prices', 'Subtotal (₹)', 'Delivery Charges (₹)',
      'Total Amount (₹)', 'Payment Method', 'UPI ID', 'Payment Status',
      'Transaction ID', 'Latitude', 'Longitude', 'Map Link', 'Order Source'
    ];

    function escapeCSV(val) {
      if (val === null || val === undefined) return '';
      const str = String(val);
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return '"' + str.replace(/"/g, '""') + '"';
      }
      return str;
    }

    const rows = orders.map(order => {
      return [
        order.order_id,
        order.order_date,
        order.customer_name,
        order.customer_phone,
        order.delivery_address,
        order.distance_km,
        order.items_list,
        order.quantities,
        order.item_prices,
        order.subtotal,
        order.delivery_charges,
        order.total_amount,
        order.payment_method,
        order.upi_id,
        order.payment_status,
        order.transaction_id,
        order.customer_lat,
        order.customer_lon,
        order.map_link,
        order.order_source
      ].map(escapeCSV).join(',');
    });

    // BOM for Excel UTF-8 compatibility
    const bom = '\uFEFF';
    const csv = bom + headers.map(escapeCSV).join(',') + '\r\n' + rows.join('\r\n');

    const filename = `orders_export_${new Date().toISOString().slice(0, 10)}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);

  } catch (err) {
    console.error('❌ CSV export error:', err.message);
    res.status(500).json({ error: 'Failed to export orders' });
  }
});

/* ===== START SERVER ===== */
if (process.env.VERCEL === '1') {
  module.exports = app;
} else {
  app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════╗
║  🍹 Ganesh Fresh Juice Centre — Server Running  ║
╠══════════════════════════════════════════════════╣
║  Frontend : http://localhost:${PORT}               ║
║  Admin    : http://localhost:${PORT}/admin          ║
║  Admin ID : ${ADMIN_USER.padEnd(36)}║
╚══════════════════════════════════════════════════╝
    `);
  });
}
