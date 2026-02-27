/**
 * Ganesh Fresh Juice Centre — Backend Server
 * Stores WhatsApp orders in SQLite (sql.js), provides admin panel with CSV export.
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const IS_VERCEL = process.env.VERCEL === '1';
const DB_PATH = IS_VERCEL
  ? path.join('/tmp', 'orders.db')
  : path.join(__dirname, 'orders.db');

/* ===== ADMIN CREDENTIALS (override via env vars) ===== */
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'ganesh@2025';

/* ===== DATABASE SETUP ===== */
let db;

async function loadSqlJs() {
  if (IS_VERCEL) {
    /* Vercel serverless: use pure-JS ASM version (no WASM binary needed) */
    const initSqlJs = require('sql.js/dist/sql-asm.js');
    return await initSqlJs();
  }
  /* Local: use WASM version (faster) */
  const initSqlJs = require('sql.js');
  return await initSqlJs({
    locateFile: file => path.join(__dirname, 'node_modules', 'sql.js', 'dist', file)
  });
}

async function initDB() {
  const SQL = await loadSqlJs();

  // Load existing DB file or create new
  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id          TEXT UNIQUE NOT NULL,
      order_date        TEXT NOT NULL,
      customer_name     TEXT DEFAULT '',
      customer_phone    TEXT DEFAULT '',
      delivery_address  TEXT DEFAULT '',
      distance_km       REAL DEFAULT 0,
      items_list        TEXT DEFAULT '',
      quantities        TEXT DEFAULT '',
      item_prices       TEXT DEFAULT '',
      subtotal          REAL DEFAULT 0,
      delivery_charges  REAL DEFAULT 0,
      total_amount      REAL DEFAULT 0,
      payment_method    TEXT DEFAULT '',
      upi_id            TEXT DEFAULT '',
      payment_status    TEXT DEFAULT 'Paid',
      transaction_id    TEXT DEFAULT '',
      customer_lat      REAL DEFAULT NULL,
      customer_lon      REAL DEFAULT NULL,
      map_link          TEXT DEFAULT '',
      order_source      TEXT DEFAULT 'WhatsApp',
      created_at        TEXT DEFAULT (datetime('now'))
    );
  `);

  /* Table columns are now defined in CREATE TABLE IF NOT EXISTS above */

  saveDB();
  console.log('✅ Database initialized');
}

function saveDB() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

/* ===== PENDING PAYMENTS STORE (in-memory, expires after 30 min) ===== */
const pendingPayments = new Map();
const PAYMENT_EXPIRY_MS = 30 * 60 * 1000;

/* Clean up expired pending payments every 5 minutes */
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of pendingPayments) {
    if (now - data.createdAt > PAYMENT_EXPIRY_MS) pendingPayments.delete(token);
  }
}, 5 * 60 * 1000);

/* ===== SESSION STORE (in-memory) ===== */
const sessions = new Map();

function createSession(username) {
  const token = uuidv4();
  sessions.set(token, { username, createdAt: Date.now() });
  return token;
}

function validateSession(token) {
  if (!token) return false;
  const session = sessions.get(token);
  if (!session) return false;
  // Sessions expire after 24 hours
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    sessions.delete(token);
    return false;
  }
  return true;
}

/* ===== MIDDLEWARE ===== */
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/* Ensure DB is initialized before handling any request (needed for Vercel serverless) */
let dbReady = null;
app.use(async (req, res, next) => {
  try {
    if (!db) {
      if (!dbReady) dbReady = initDB();
      await dbReady;
    }
    next();
  } catch (err) {
    console.error('❌ DB initialization failed:', err.message);
    dbReady = null; /* allow retry on next request */
    res.status(500).json({ error: 'Server initialization failed. Please try again.' });
  }
});

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
  res.json({ status: 'ok', db: !!db, vercel: IS_VERCEL, time: new Date().toISOString() });
});

/* ===== STATIC FILES (serve the existing frontend) ===== */
app.use(express.static(__dirname, {
  index: 'index.html',
  extensions: ['html']
}));

/* ===== ORDER API (COD orders only — UPI orders go through /api/payment/verify) ===== */
app.post('/api/orders', (req, res) => {
  try {
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
    const existing = db.exec('SELECT order_id FROM orders WHERE order_id = ?', [body.orderNo]);
    if (existing.length > 0 && existing[0].values.length > 0) {
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

    db.run(`
      INSERT INTO orders (
        order_id, order_date, customer_name, customer_phone,
        delivery_address, distance_km, items_list, quantities,
        item_prices, subtotal, delivery_charges, total_amount,
        payment_method, upi_id, payment_status, transaction_id,
        customer_lat, customer_lon, map_link, order_source
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      orderData.order_id, orderData.order_date, orderData.customer_name, orderData.customer_phone,
      orderData.delivery_address, orderData.distance_km, orderData.items_list, orderData.quantities,
      orderData.item_prices, orderData.subtotal, orderData.delivery_charges, orderData.total_amount,
      orderData.payment_method, orderData.upi_id, orderData.payment_status, orderData.transaction_id,
      orderData.customer_lat, orderData.customer_lon, orderData.map_link, orderData.order_source
    ]);

    saveDB();

    console.log(`✅ COD Order ${orderData.order_id} stored successfully`);
    res.status(201).json({
      success: true,
      message: 'COD order stored successfully',
      orderId: orderData.order_id
    });

  } catch (err) {
    console.error('❌ COD order error:', err.message);
    if (err.message?.includes('UNIQUE constraint')) {
      return res.status(409).json({ error: 'Duplicate order', message: err.message });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

/* ===== PAYMENT INITIATION ===== */
app.post('/api/payment/initiate', (req, res) => {
  try {
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
app.post('/api/payment/verify', (req, res) => {
  try {
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
    const dupCheck = db.exec('SELECT order_id FROM orders WHERE transaction_id = ?', [txnId]);
    if (dupCheck.length > 0 && dupCheck[0].values.length > 0) {
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

    db.run(`
      INSERT INTO orders (
        order_id, order_date, customer_name, customer_phone,
        delivery_address, distance_km, items_list, quantities,
        item_prices, subtotal, delivery_charges, total_amount,
        payment_method, upi_id, payment_status, transaction_id,
        customer_lat, customer_lon, map_link, order_source
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      orderData.order_id, orderData.order_date, orderData.customer_name, orderData.customer_phone,
      orderData.delivery_address, orderData.distance_km, orderData.items_list, orderData.quantities,
      orderData.item_prices, orderData.subtotal, orderData.delivery_charges, orderData.total_amount,
      orderData.payment_method, orderData.upi_id, orderData.payment_status, orderData.transaction_id,
      orderData.customer_lat, orderData.customer_lon, orderData.map_link, orderData.order_source
    ]);

    saveDB();

    /* Cleanup pending entry */
    pendingPayments.delete(paymentToken);

    console.log(`✅ Payment verified & order ${orderData.order_id} created (TXN: ${txnId})`);
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
    if (err.message?.includes('UNIQUE constraint')) {
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
app.get('/api/admin/orders', requireAuth, (req, res) => {
  try {
    const result = db.exec('SELECT * FROM orders ORDER BY id DESC');
    if (!result.length) {
      return res.json({ success: true, count: 0, orders: [] });
    }

    const columns = result[0].columns;
    const orders = result[0].values.map(row => {
      const obj = {};
      columns.forEach((col, i) => obj[col] = row[i]);
      return obj;
    });

    res.json({ success: true, count: orders.length, orders });
  } catch (err) {
    console.error('❌ Fetch orders error:', err.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

/* Export orders as CSV (admin only) */
app.get('/api/admin/export/csv', requireAuth, (req, res) => {
  try {
    const result = db.exec('SELECT * FROM orders ORDER BY id DESC');

    const headers = [
      'Order ID', 'Date & Time', 'Customer Name', 'Phone Number',
      'Delivery Address', 'Distance (km)', 'Items', 'Quantities',
      'Item Prices', 'Subtotal (₹)', 'Delivery Charges (₹)',
      'Total Amount (₹)', 'Payment Method', 'UPI ID',
      'Latitude', 'Longitude', 'Map Link', 'Order Source'
    ];

    function escapeCSV(val) {
      if (val === null || val === undefined) return '';
      const str = String(val);
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return '"' + str.replace(/"/g, '""') + '"';
      }
      return str;
    }

    let rows = [];
    if (result.length) {
      rows = result[0].values.map(row => {
        // Extract relevant columns (skip id and created_at)
        return [
          row[1],  // order_id
          row[2],  // order_date
          row[3],  // customer_name
          row[4],  // customer_phone
          row[5],  // delivery_address
          row[6],  // distance_km
          row[7],  // items_list
          row[8],  // quantities
          row[9],  // item_prices
          row[10], // subtotal
          row[11], // delivery_charges
          row[12], // total_amount
          row[13], // payment_method
          row[14], // upi_id
          row[15], // customer_lat
          row[16], // customer_lon
          row[17], // map_link
          row[18], // order_source
        ].map(escapeCSV).join(',');
      });
    }

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
if (IS_VERCEL) {
  /* Vercel serverless — export the Express app, DB inits lazily via middleware */
  module.exports = app;
} else {
  /* Local development — init DB and start listening */
  initDB().then(() => {
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
  }).catch(err => {
    console.error('❌ Failed to start server:', err);
    process.exit(1);
  });
}
