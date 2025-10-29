const express = require('express');
const path = require('path');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// Basic middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session store
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: '.' }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

// Create or open database
const dbFile = path.join(__dirname, 'data.db');
const db = new sqlite3.Database(dbFile);

// Initialize users table
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT
  )`);
});

// Helper: ensure authenticated
function ensureAuthenticated(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.redirect('/login');
}

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.session.userId ? { id: req.session.userId, email: req.session.email, name: req.session.name } : null });
});

app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

app.post('/signup', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.render('signup', { error: 'Email and password are required.' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)');
    stmt.run(email.toLowerCase(), hash, name || null, function (err) {
      if (err) {
        console.error(err);
        return res.render('signup', { error: 'A user with that email may already exist.' });
      }
      // auto-login after signup
      req.session.userId = this.lastID;
      req.session.email = email.toLowerCase();
      req.session.name = name || null;
      res.redirect('/dashboard');
    });
    stmt.finalize();
  } catch (e) {
    console.error(e);
    res.render('signup', { error: 'Unexpected error.' });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.render('login', { error: 'Email and password are required.' });

  db.get('SELECT id, email, password_hash, name FROM users WHERE email = ?', [email.toLowerCase()], async (err, row) => {
    if (err) {
      console.error(err);
      return res.render('login', { error: 'Unexpected error.' });
    }
    if (!row) return res.render('login', { error: 'Invalid email or password.' });

    const match = await bcrypt.compare(password, row.password_hash);
    if (!match) return res.render('login', { error: 'Invalid email or password.' });

    req.session.userId = row.id;
    req.session.email = row.email;
    req.session.name = row.name;
    res.redirect('/dashboard');
  });
});

app.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.render('dashboard', { user: { id: req.session.userId, email: req.session.email, name: req.session.name } });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// Simple health route
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
