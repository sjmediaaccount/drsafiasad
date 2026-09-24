const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 8000;
const SALT_ROUNDS = 12;
const DB_PATH = path.join(__dirname, 'clinic.db');

let db;

// ── Database Setup ──────────────────────────────────────────────────
async function initDatabase() {
  const SQL = await initSqlJs();

  // Load existing database if it exists
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL DEFAULT '',
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'patient' CHECK(role IN ('patient', 'admin')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS appointments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      date TEXT NOT NULL,
      time TEXT NOT NULL,
      condition_type TEXT NOT NULL,
      contact TEXT NOT NULL DEFAULT '',
      notes TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending', 'Confirmed', 'Completed', 'Cancelled')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Seed admin account if none exists
  const adminCheck = db.exec("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
  if (adminCheck.length === 0) {
    const hash = bcrypt.hashSync('admin123', SALT_ROUNDS);
    db.run('INSERT INTO users (name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)',
      ['Admin', 'admin@clinic.com', '', hash, 'admin']);
    saveDb();
    console.log('✓ Default admin created: admin@clinic.com / admin123');
  }
}

function saveDb() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// Helper: run sql.js query and return rows as array of objects
function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

function dbGet(sql, params = []) {
  const rows = dbAll(sql, params);
  return rows.length > 0 ? rows[0] : null;
}

function dbRun(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  stmt.step();
  stmt.free();
  saveDb();
  // Return last insert id
  const result = db.exec("SELECT last_insert_rowid() as id");
  return result.length > 0 ? result[0].values[0][0] : null;
}

// ── Middleware ───────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'dr-safi-clinic-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static files
app.use(express.static(__dirname, {
  index: 'index.html',
  extensions: ['html']
}));

// ── Auth Middleware Helpers ──────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated. Please log in.' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId || req.session.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  next();
}

// ── Auth Routes ─────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }
    if (name.trim().length < 2) {
      return res.status(400).json({ error: 'Name must be at least 2 characters.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }

    const existing = dbGet('SELECT id FROM users WHERE email = ?', [email.toLowerCase().trim()]);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    dbRun(
      'INSERT INTO users (name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)',
      [name.trim(), email.toLowerCase().trim(), phone || '', hash, 'patient']
    );

    // Query the newly created user to get the real ID
    const newUser = dbGet('SELECT id, name, email, phone, role FROM users WHERE email = ?', [email.toLowerCase().trim()]);

    req.session.userId = newUser.id;
    req.session.role = 'patient';
    req.session.userName = newUser.name;

    res.status(201).json({
      message: 'Account created successfully.',
      user: newUser
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = dbGet('SELECT * FROM users WHERE email = ?', [email.toLowerCase().trim()]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.userName = user.name;

    res.json({
      message: 'Logged in successfully.',
      user: { id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ message: 'Logged out successfully.' });
  });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  const user = dbGet('SELECT id, name, email, phone, role FROM users WHERE id = ?', [req.session.userId]);
  if (!user) {
    return res.status(401).json({ error: 'User not found.' });
  }
  res.json({ user });
});

// Setup/Create Admin Account
app.post('/api/auth/setup-admin', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }

    const adminName = (name && name.trim()) ? name.trim() : 'Admin';
    const adminEmail = email.toLowerCase().trim();
    const hash = await bcrypt.hash(password, SALT_ROUNDS);

    const existingAdmin = dbGet("SELECT id FROM users WHERE role = 'admin' OR email = ?", [adminEmail]);

    if (existingAdmin) {
      dbRun('UPDATE users SET name = ?, email = ?, password_hash = ?, role = ? WHERE id = ?',
        [adminName, adminEmail, hash, 'admin', existingAdmin.id]);
    } else {
      dbRun('INSERT INTO users (name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)',
        [adminName, adminEmail, '', hash, 'admin']);
    }

    const adminUser = dbGet("SELECT id, name, email, role FROM users WHERE role = 'admin' LIMIT 1");

    req.session.userId = adminUser.id;
    req.session.role = 'admin';
    req.session.userName = adminUser.name;

    res.json({
      message: 'Admin credentials created and logged in successfully!',
      user: adminUser
    });
  } catch (err) {
    console.error('Setup admin error:', err);
    res.status(500).json({ error: 'Failed to save admin credentials.' });
  }
});

// Direct One-Click Admin Auto Login
app.get('/api/auth/one-click-admin', (req, res) => {
  const adminUser = dbGet("SELECT id, name, email, role FROM users WHERE role = 'admin' LIMIT 1");
  if (!adminUser) {
    const hash = bcrypt.hashSync('admin123', SALT_ROUNDS);
    dbRun('INSERT INTO users (name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)',
      ['Admin', 'admin@clinic.com', '', hash, 'admin']);
  }
  const activeAdmin = dbGet("SELECT id, name, email, role FROM users WHERE role = 'admin' LIMIT 1");
  req.session.userId = activeAdmin.id;
  req.session.role = 'admin';
  req.session.userName = activeAdmin.name;

  res.redirect('/admin-dashboard.html');
});

// ── Patient Routes ──────────────────────────────────────────────────
app.get('/api/appointments', requireAuth, (req, res) => {
  const appointments = dbAll('SELECT * FROM appointments WHERE user_id = ? ORDER BY created_at DESC', [req.session.userId]);
  res.json({ appointments });
});

app.post('/api/appointments', requireAuth, (req, res) => {
  const { date, time, condition_type, contact, notes } = req.body;

  if (!date || !time || !condition_type) {
    return res.status(400).json({ error: 'Date, time, and condition are required.' });
  }

  dbRun(
    'INSERT INTO appointments (user_id, date, time, condition_type, contact, notes) VALUES (?, ?, ?, ?, ?, ?)',
    [req.session.userId, date, time, condition_type, contact || '', notes || '']
  );

  const appointment = dbGet('SELECT * FROM appointments WHERE user_id = ? ORDER BY id DESC LIMIT 1', [req.session.userId]);
  res.status(201).json({ message: 'Appointment booked successfully.', appointment });
});

app.get('/api/profile', requireAuth, (req, res) => {
  const user = dbGet('SELECT id, name, email, phone, role, created_at FROM users WHERE id = ?', [req.session.userId]);
  res.json({ user });
});

app.put('/api/profile', requireAuth, (req, res) => {
  const { name, email, phone } = req.body;

  if (!name || !email) {
    return res.status(400).json({ error: 'Name and email are required.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  const existing = dbGet('SELECT id FROM users WHERE email = ? AND id != ?', [email.toLowerCase().trim(), req.session.userId]);
  if (existing) {
    return res.status(409).json({ error: 'This email is already used by another account.' });
  }

  dbRun('UPDATE users SET name = ?, email = ?, phone = ? WHERE id = ?',
    [name.trim(), email.toLowerCase().trim(), phone || '', req.session.userId]);

  req.session.userName = name.trim();

  const user = dbGet('SELECT id, name, email, phone, role FROM users WHERE id = ?', [req.session.userId]);
  res.json({ message: 'Profile updated.', user });
});

// ── Admin Routes ────────────────────────────────────────────────────
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const totalAppointments = dbGet('SELECT COUNT(*) as count FROM appointments').count;
  const pendingAppointments = dbGet("SELECT COUNT(*) as count FROM appointments WHERE status = 'Pending'").count;
  const totalPatients = dbGet("SELECT COUNT(*) as count FROM users WHERE role = 'patient'").count;
  res.json({ totalAppointments, pendingAppointments, totalPatients });
});

app.get('/api/admin/appointments', requireAdmin, (req, res) => {
  const { status, search, date } = req.query;
  let sql = `
    SELECT a.*, u.name as patient_name, u.email as patient_email, u.phone as patient_phone
    FROM appointments a
    JOIN users u ON a.user_id = u.id
    WHERE 1=1
  `;
  const params = [];

  if (status && status !== 'all') {
    sql += ' AND a.status = ?';
    params.push(status);
  }
  if (search) {
    sql += ' AND (u.name LIKE ? OR u.email LIKE ? OR u.phone LIKE ?)';
    const like = `%${search}%`;
    params.push(like, like, like);
  }
  if (date) {
    sql += ' AND a.date = ?';
    params.push(date);
  }

  sql += ' ORDER BY a.created_at DESC';

  const appointments = dbAll(sql, params);
  res.json({ appointments });
});

app.patch('/api/admin/appointments/:id', requireAdmin, (req, res) => {
  const { status } = req.body;
  const validStatuses = ['Pending', 'Confirmed', 'Completed', 'Cancelled'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status.' });
  }

  dbRun('UPDATE appointments SET status = ? WHERE id = ?', [status, parseInt(req.params.id)]);
  const appointment = dbGet(`
    SELECT a.*, u.name as patient_name, u.email as patient_email, u.phone as patient_phone
    FROM appointments a JOIN users u ON a.user_id = u.id WHERE a.id = ?
  `, [parseInt(req.params.id)]);

  res.json({ message: 'Status updated.', appointment });
});

app.get('/api/admin/patients', requireAdmin, (req, res) => {
  const patients = dbAll(`
    SELECT u.id, u.name, u.email, u.phone, u.created_at,
           (SELECT COUNT(*) FROM appointments WHERE user_id = u.id) as appointment_count
    FROM users u
    WHERE u.role = 'patient'
    ORDER BY u.created_at DESC
  `);
  res.json({ patients });
});

app.get('/api/admin/patients/:id/appointments', requireAdmin, (req, res) => {
  const patient = dbGet('SELECT id, name, email, phone FROM users WHERE id = ? AND role = ?', [parseInt(req.params.id), 'patient']);
  if (!patient) {
    return res.status(404).json({ error: 'Patient not found.' });
  }
  const appointments = dbAll('SELECT * FROM appointments WHERE user_id = ? ORDER BY created_at DESC', [parseInt(req.params.id)]);
  res.json({ patient, appointments });
});

// ── Start Server ────────────────────────────────────────────────────
async function start() {
  await initDatabase();
  app.listen(PORT, () => {
    console.log(`\n🌿 Dr. Safi Asad Clinic Server`);
    console.log(`   ──────────────────────────`);
    console.log(`   Website:  http://localhost:${PORT}`);
    console.log(`   Admin:    http://localhost:${PORT}/admin.html`);
    console.log(`   Status:   Running\n`);
  });
}

start().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
