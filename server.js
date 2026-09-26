const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 8000;
const SALT_ROUNDS = 12;
const DB_PATH = path.join(__dirname, 'clinic.db');

// ── Supabase Configuration ─────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://jtnzjmcejnmeyyzeqcel.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'sb_publishable_w6OkN7lfxkzcY4NHb9YASw_MiajRLxP';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
let useSupabase = true;
let db;

// ── Database Setup ──────────────────────────────────────────────────
async function initDatabase() {
  try {
    const { data, error } = await supabase.from('users').select('id').limit(1);
    if (!error || error.code === 'PGRST205') {
      useSupabase = true;
      console.log('⚡ Connected to Supabase backend!');
    } else {
      console.log(`⚠️ Supabase Notice: ${error.message}`);
    }
  } catch (err) {
    console.log('⚠️ Supabase connection error:', err.message);
  }

  if (!process.env.VERCEL) {
    try {
      const SQL = await initSqlJs();
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

      const adminCheck = db.exec("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
      if (adminCheck.length === 0) {
        const hash = bcrypt.hashSync('admin123', SALT_ROUNDS);
        db.run('INSERT INTO users (name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)',
          ['Admin', 'admin@clinic.com', '+92 300 1234567', hash, 'admin']);
        saveDb();
      }
    } catch (e) {
      console.warn('SQLite init warning:', e.message);
    }
  }
}

function saveDb() {
  if (db && !process.env.VERCEL) {
    try {
      const data = db.export();
      const buffer = Buffer.from(data);
      fs.writeFileSync(DB_PATH, buffer);
    } catch (e) {
      console.warn('Could not save SQLite to disk:', e.message);
    }
  }
}

// ── SQLite Helpers ──────────────────────────────────────────────────
function dbAll(sql, params = []) {
  if (!db) return [];
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
  if (!db) return null;
  const stmt = db.prepare(sql);
  stmt.bind(params);
  stmt.step();
  stmt.free();
  saveDb();
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
  secret: process.env.SESSION_SECRET || 'dr-safi-clinic-secret-key-vercel',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static files from public and root
app.use(express.static(path.join(__dirname, 'public'), {
  index: 'index.html',
  extensions: ['html', 'htm', 'css', 'png', 'jpg', 'jpeg', 'jfif', 'js', 'json']
}));
app.use(express.static(__dirname, {
  index: 'index.html',
  extensions: ['html', 'htm', 'css', 'png', 'jpg', 'jpeg', 'jfif', 'js', 'json']
}));

// Route Handlers for HTML Pages
app.get(['/', '/index', '/index.html'], (req, res) => {
  const filePath = fs.existsSync(path.join(__dirname, 'public', 'index.html'))
    ? path.join(__dirname, 'public', 'index.html')
    : path.join(__dirname, 'index.html');
  res.sendFile(filePath);
});

app.get(['/dashboard', '/dashboard.html'], (req, res) => {
  const filePath = fs.existsSync(path.join(__dirname, 'public', 'dashboard.html'))
    ? path.join(__dirname, 'public', 'dashboard.html')
    : path.join(__dirname, 'dashboard.html');
  res.sendFile(filePath);
});

app.get(['/admin', '/admin.html'], (req, res) => {
  const filePath = fs.existsSync(path.join(__dirname, 'public', 'admin.html'))
    ? path.join(__dirname, 'public', 'admin.html')
    : path.join(__dirname, 'admin.html');
  res.sendFile(filePath);
});

app.get(['/admin-dashboard', '/admin-dashboard.html'], (req, res) => {
  const filePath = fs.existsSync(path.join(__dirname, 'public', 'admin-dashboard.html'))
    ? path.join(__dirname, 'public', 'admin-dashboard.html')
    : path.join(__dirname, 'admin-dashboard.html');
  res.sendFile(filePath);
});

app.get(['/admin-setup', '/admin-setup.html'], (req, res) => {
  const filePath = fs.existsSync(path.join(__dirname, 'public', 'admin-setup.html'))
    ? path.join(__dirname, 'public', 'admin-setup.html')
    : path.join(__dirname, 'admin-setup.html');
  res.sendFile(filePath);
});

// Expose Supabase Config endpoint to frontend
app.get('/api/config/supabase', (req, res) => {
  res.json({
    supabaseUrl: SUPABASE_URL,
    supabaseKey: SUPABASE_KEY,
    useSupabase
  });
});

// ── Auth Middleware Helpers ──────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated. Please log in.' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId || req.session.role !== 'admin') {
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

    const cleanEmail = email.toLowerCase().trim();
    const cleanName = name.trim();
    const cleanPhone = phone || '';
    const hash = await bcrypt.hash(password, SALT_ROUNDS);

    if (useSupabase) {
      const { data: existing } = await supabase.from('users').select('id').eq('email', cleanEmail).maybeSingle();
      if (existing) {
        return res.status(409).json({ error: 'An account with this email already exists.' });
      }

      const { data: newUser, error } = await supabase.from('users').insert([{
        name: cleanName,
        email: cleanEmail,
        phone: cleanPhone,
        password_hash: hash,
        role: 'patient'
      }]).select('id, name, email, phone, role').single();

      if (error) throw error;

      req.session.userId = newUser.id;
      req.session.role = 'patient';
      req.session.userName = newUser.name;

      return res.status(201).json({ message: 'Account created successfully.', user: newUser });
    } else {
      const existing = dbGet('SELECT id FROM users WHERE email = ?', [cleanEmail]);
      if (existing) {
        return res.status(409).json({ error: 'An account with this email already exists.' });
      }

      dbRun('INSERT INTO users (name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)',
        [cleanName, cleanEmail, cleanPhone, hash, 'patient']);

      const newUser = dbGet('SELECT id, name, email, phone, role FROM users WHERE email = ?', [cleanEmail]);
      req.session.userId = newUser.id;
      req.session.role = 'patient';
      req.session.userName = newUser.name;

      return res.status(201).json({ message: 'Account created successfully.', user: newUser });
    }
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: err.message || 'Something went wrong. Please try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const cleanEmail = email.toLowerCase().trim();
    let user;

    if (useSupabase) {
      const { data, error } = await supabase.from('users').select('*').eq('email', cleanEmail).maybeSingle();
      if (error || !data) {
        return res.status(401).json({ error: 'Invalid email or password.' });
      }
      user = data;
    } else {
      user = dbGet('SELECT * FROM users WHERE email = ?', [cleanEmail]);
      if (!user) {
        return res.status(401).json({ error: 'Invalid email or password.' });
      }
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
  if (req.session) {
    req.session.destroy(() => {
      res.json({ message: 'Logged out successfully.' });
    });
  } else {
    res.json({ message: 'Logged out.' });
  }
});

app.get('/api/auth/me', async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  if (useSupabase) {
    const { data: user, error } = await supabase.from('users').select('id, name, email, phone, role').eq('id', req.session.userId).maybeSingle();
    if (error || !user) {
      return res.status(401).json({ error: 'User not found.' });
    }
    return res.json({ user });
  } else {
    const user = dbGet('SELECT id, name, email, phone, role FROM users WHERE id = ?', [req.session.userId]);
    if (!user) {
      return res.status(401).json({ error: 'User not found.' });
    }
    return res.json({ user });
  }
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

    if (useSupabase) {
      const { data: existingAdmin } = await supabase.from('users').select('id').or(`role.eq.admin,email.eq.${adminEmail}`).limit(1);

      if (existingAdmin && existingAdmin.length > 0) {
        await supabase.from('users').update({ name: adminName, email: adminEmail, password_hash: hash, role: 'admin' }).eq('id', existingAdmin[0].id);
      } else {
        await supabase.from('users').insert([{ name: adminName, email: adminEmail, phone: '', password_hash: hash, role: 'admin' }]);
      }

      const { data: adminUser } = await supabase.from('users').select('id, name, email, role').eq('role', 'admin').limit(1).single();
      req.session.userId = adminUser.id;
      req.session.role = 'admin';
      req.session.userName = adminUser.name;

      return res.json({ message: 'Admin credentials created and logged in successfully!', user: adminUser });
    } else {
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
      return res.json({ message: 'Admin credentials created and logged in successfully!', user: adminUser });
    }
  } catch (err) {
    console.error('Setup admin error:', err);
    res.status(500).json({ error: 'Failed to save admin credentials.' });
  }
});

// Direct One-Click Admin Auto Login
app.get('/api/auth/one-click-admin', async (req, res) => {
  try {
    if (useSupabase) {
      let { data: adminUser } = await supabase.from('users').select('id, name, email, role').eq('role', 'admin').limit(1).maybeSingle();
      if (!adminUser) {
        const hash = bcrypt.hashSync('admin123', SALT_ROUNDS);
        const { data: created } = await supabase.from('users').insert([{
          name: 'Admin', email: 'admin@clinic.com', phone: '+92 300 1234567', password_hash: hash, role: 'admin'
        }]).select().single();
        adminUser = created;
      }
      req.session.userId = adminUser.id;
      req.session.role = 'admin';
      req.session.userName = adminUser.name;
    } else {
      let adminUser = dbGet("SELECT id, name, email, role FROM users WHERE role = 'admin' LIMIT 1");
      if (!adminUser) {
        const hash = bcrypt.hashSync('admin123', SALT_ROUNDS);
        dbRun('INSERT INTO users (name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)',
          ['Admin', 'admin@clinic.com', '+92 300 1234567', hash, 'admin']);
        adminUser = dbGet("SELECT id, name, email, role FROM users WHERE role = 'admin' LIMIT 1");
      }
      req.session.userId = adminUser.id;
      req.session.role = 'admin';
      req.session.userName = adminUser.name;
    }
    res.redirect('/admin-dashboard.html');
  } catch (err) {
    console.error('One-click admin error:', err);
    res.redirect('/admin.html');
  }
});

// ── Patient Routes ──────────────────────────────────────────────────
app.get('/api/appointments', requireAuth, async (req, res) => {
  try {
    if (useSupabase) {
      const { data: appointments, error } = await supabase
        .from('appointments')
        .select('*')
        .eq('user_id', req.session.userId)
        .order('created_at', { ascending: false });

      if (error) throw error;
      return res.json({ appointments: appointments || [] });
    } else {
      const appointments = dbAll('SELECT * FROM appointments WHERE user_id = ? ORDER BY created_at DESC', [req.session.userId]);
      return res.json({ appointments });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to load appointments.' });
  }
});

app.post('/api/appointments', requireAuth, async (req, res) => {
  try {
    const { date, time, condition_type, contact, notes } = req.body;

    if (!date || !time || !condition_type) {
      return res.status(400).json({ error: 'Date, time, and condition are required.' });
    }

    if (useSupabase) {
      const { data: appointment, error } = await supabase
        .from('appointments')
        .insert([{
          user_id: req.session.userId,
          date,
          time,
          condition_type,
          contact: contact || '',
          notes: notes || ''
        }])
        .select('*')
        .single();

      if (error) throw error;
      return res.status(201).json({ message: 'Appointment booked successfully.', appointment });
    } else {
      dbRun(
        'INSERT INTO appointments (user_id, date, time, condition_type, contact, notes) VALUES (?, ?, ?, ?, ?, ?)',
        [req.session.userId, date, time, condition_type, contact || '', notes || '']
      );
      const appointment = dbGet('SELECT * FROM appointments WHERE user_id = ? ORDER BY id DESC LIMIT 1', [req.session.userId]);
      return res.status(201).json({ message: 'Appointment booked successfully.', appointment });
    }
  } catch (err) {
    console.error('Book appointment error:', err);
    res.status(500).json({ error: 'Failed to book appointment.' });
  }
});

app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    if (useSupabase) {
      const { data: user, error } = await supabase
        .from('users')
        .select('id, name, email, phone, role, created_at')
        .eq('id', req.session.userId)
        .single();
      if (error) throw error;
      return res.json({ user });
    } else {
      const user = dbGet('SELECT id, name, email, phone, role, created_at FROM users WHERE id = ?', [req.session.userId]);
      return res.json({ user });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to load profile.' });
  }
});

app.put('/api/profile', requireAuth, async (req, res) => {
  try {
    const { name, email, phone } = req.body;

    if (!name || !email) {
      return res.status(400).json({ error: 'Name and email are required.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const cleanName = name.trim();
    const cleanPhone = phone || '';

    if (useSupabase) {
      const { data: existing } = await supabase
        .from('users')
        .select('id')
        .eq('email', cleanEmail)
        .neq('id', req.session.userId)
        .maybeSingle();

      if (existing) {
        return res.status(409).json({ error: 'This email is already used by another account.' });
      }

      const { data: user, error } = await supabase
        .from('users')
        .update({ name: cleanName, email: cleanEmail, phone: cleanPhone })
        .eq('id', req.session.userId)
        .select('id, name, email, phone, role')
        .single();

      if (error) throw error;
      req.session.userName = cleanName;
      return res.json({ message: 'Profile updated.', user });
    } else {
      const existing = dbGet('SELECT id FROM users WHERE email = ? AND id != ?', [cleanEmail, req.session.userId]);
      if (existing) {
        return res.status(409).json({ error: 'This email is already used by another account.' });
      }

      dbRun('UPDATE users SET name = ?, email = ?, phone = ? WHERE id = ?', [cleanName, cleanEmail, cleanPhone, req.session.userId]);
      req.session.userName = cleanName;
      const user = dbGet('SELECT id, name, email, phone, role FROM users WHERE id = ?', [req.session.userId]);
      return res.json({ message: 'Profile updated.', user });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to update profile.' });
  }
});

// ── Admin Routes ────────────────────────────────────────────────────
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    if (useSupabase) {
      const { count: totalAppointments } = await supabase.from('appointments').select('*', { count: 'exact', head: true });
      const { count: pendingAppointments } = await supabase.from('appointments').select('*', { count: 'exact', head: true }).eq('status', 'Pending');
      const { count: totalPatients } = await supabase.from('users').select('*', { count: 'exact', head: true }).eq('role', 'patient');

      return res.json({
        totalAppointments: totalAppointments || 0,
        pendingAppointments: pendingAppointments || 0,
        totalPatients: totalPatients || 0
      });
    } else {
      const totalAppointments = dbGet('SELECT COUNT(*) as count FROM appointments').count;
      const pendingAppointments = dbGet("SELECT COUNT(*) as count FROM appointments WHERE status = 'Pending'").count;
      const totalPatients = dbGet("SELECT COUNT(*) as count FROM users WHERE role = 'patient'").count;
      return res.json({ totalAppointments, pendingAppointments, totalPatients });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to load stats.' });
  }
});

app.get('/api/admin/appointments', requireAdmin, async (req, res) => {
  try {
    const { status, search, date } = req.query;

    if (useSupabase) {
      let query = supabase
        .from('appointments')
        .select('*, users:user_id(name, email, phone)')
        .order('created_at', { ascending: false });

      if (status && status !== 'all') {
        query = query.eq('status', status);
      }
      if (date) {
        query = query.eq('date', date);
      }

      const { data: rawAppointments, error } = await query;
      if (error) throw error;

      let appointments = (rawAppointments || []).map(a => ({
        ...a,
        patient_name: a.users?.name || 'N/A',
        patient_email: a.users?.email || 'N/A',
        patient_phone: a.users?.phone || 'N/A'
      }));

      if (search) {
        const lowerSearch = search.toLowerCase();
        appointments = appointments.filter(a =>
          a.patient_name.toLowerCase().includes(lowerSearch) ||
          a.patient_email.toLowerCase().includes(lowerSearch) ||
          a.patient_phone.toLowerCase().includes(lowerSearch)
        );
      }

      return res.json({ appointments });
    } else {
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
      return res.json({ appointments });
    }
  } catch (err) {
    console.error('Fetch admin appointments error:', err);
    res.status(500).json({ error: 'Failed to fetch appointments.' });
  }
});

app.patch('/api/admin/appointments/:id', requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const validStatuses = ['Pending', 'Confirmed', 'Completed', 'Cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status.' });
    }

    const apptId = parseInt(req.params.id);

    if (useSupabase) {
      const { data: appointment, error } = await supabase
        .from('appointments')
        .update({ status })
        .eq('id', apptId)
        .select('*, users:user_id(name, email, phone)')
        .single();

      if (error) throw error;
      const formatted = {
        ...appointment,
        patient_name: appointment.users?.name || 'N/A',
        patient_email: appointment.users?.email || 'N/A',
        patient_phone: appointment.users?.phone || 'N/A'
      };
      return res.json({ message: 'Status updated.', appointment: formatted });
    } else {
      dbRun('UPDATE status = ? WHERE id = ?', [status, apptId]);
      const appointment = dbGet(`
        SELECT a.*, u.name as patient_name, u.email as patient_email, u.phone as patient_phone
        FROM appointments a JOIN users u ON a.user_id = u.id WHERE a.id = ?
      `, [apptId]);
      return res.json({ message: 'Status updated.', appointment });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to update status.' });
  }
});

app.get('/api/admin/patients', requireAdmin, async (req, res) => {
  try {
    if (useSupabase) {
      const { data: patients, error } = await supabase
        .from('users')
        .select('id, name, email, phone, created_at, appointments(count)')
        .eq('role', 'patient')
        .order('created_at', { ascending: false });

      if (error) throw error;
      const formatted = (patients || []).map(p => ({
        id: p.id,
        name: p.name,
        email: p.email,
        phone: p.phone,
        created_at: p.created_at,
        appointment_count: p.appointments ? p.appointments[0]?.count || 0 : 0
      }));
      return res.json({ patients: formatted });
    } else {
      const patients = dbAll(`
        SELECT u.id, u.name, u.email, u.phone, u.created_at,
               (SELECT COUNT(*) FROM appointments WHERE user_id = u.id) as appointment_count
        FROM users u
        WHERE u.role = 'patient'
        ORDER BY u.created_at DESC
      `);
      return res.json({ patients });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch patients.' });
  }
});

app.get('/api/admin/patients/:id/appointments', requireAdmin, async (req, res) => {
  try {
    const patientId = parseInt(req.params.id);

    if (useSupabase) {
      const { data: patient } = await supabase.from('users').select('id, name, email, phone').eq('id', patientId).eq('role', 'patient').single();
      if (!patient) return res.status(404).json({ error: 'Patient not found.' });

      const { data: appointments } = await supabase.from('appointments').select('*').eq('user_id', patientId).order('created_at', { ascending: false });
      return res.json({ patient, appointments: appointments || [] });
    } else {
      const patient = dbGet('SELECT id, name, email, phone FROM users WHERE id = ? AND role = ?', [patientId, 'patient']);
      if (!patient) return res.status(404).json({ error: 'Patient not found.' });
      const appointments = dbAll('SELECT * FROM appointments WHERE user_id = ? ORDER BY created_at DESC', [patientId]);
      return res.json({ patient, appointments });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch patient appointments.' });
  }
});

// Initialize DB asynchronously
initDatabase().catch(err => console.error('DB init error:', err));

// Export Express App for Vercel Serverless Function
module.exports = app;

// Run standalone server if not on Vercel
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`\n🌿 Dr. Safi Asad Clinic Server running on http://localhost:${PORT}`);
  });
}
