// server.js
// npm install express pg bcrypt nodemailer jsonwebtoken cors

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');

const app = express();

// ─── VARIABLES (ANTES .env) ─────────────────────────────
const DATABASE_URL = "postgresql://postgres.mawkbhhmjgbxqdqhvfyd:AguaDeVida123@aws-1-us-east-1.pooler.supabase.com:5432/postgres";

const EMAIL_USER = "rubenmendozad2007@gmail.com";
const EMAIL_PASS = "dyfqbxvgivfpkcdk";

const JWT_SECRET = "9abecaaef3bfab885d54e2a6c696a8fb725f459716e6fba7a3474a0e5439746c";

const BACKEND_URL = "https://adv-backend-two.vercel.app";
const FRONTEND_URL = "http://localhost:4200";

// ─── CONFIG ─────────────────────────────────────────────
app.use(express.json());
app.use(cors({
  origin: true,
  credentials: true
}));

// ─── DB ─────────────────────────────────────────────────
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ─── MAIL ───────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

// ─── UTIL ───────────────────────────────────────────────
function generateConfirmToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ─── AUTH ───────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'No autorizado.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido.' });
    req.user = user;
    next();
  });
}

// ─── LOGIN ──────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE correo = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales incorrectas.' });
    }

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.contrasena);
    if (!match) {
      return res.status(401).json({ message: 'Credenciales incorrectas.' });
    }

    const confirmToken = generateConfirmToken();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await pool.query(
      `UPDATE usuarios 
       SET confirm_token = $1, confirm_token_expires = $2 
       WHERE id = $3`,
      [confirmToken, expiresAt, user.id]
    );

    const confirmLink = `${BACKEND_URL}/api/confirm/${confirmToken}`;

    await transporter.sendMail({
      from: `"Panel Admin" <${EMAIL_USER}>`,
      to: user.correo,
      subject: 'Confirma tu inicio de sesión',
      html: `<a href="${confirmLink}">Confirmar</a>`
    });

    res.json({ message: 'Correo enviado.' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error interno.' });
  }
});

// ─── CONFIRM ────────────────────────────────────────────
app.get('/api/confirm/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const result = await pool.query(
      `SELECT * FROM usuarios 
       WHERE confirm_token = $1 AND confirm_token_expires > NOW()`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.send('Token inválido');
    }

    const user = result.rows[0];

    await pool.query(
      `UPDATE usuarios 
       SET confirm_token = NULL, confirm_token_expires = NULL 
       WHERE id = $1`,
      [user.id]
    );

    const sessionToken = jwt.sign(
      { id: user.id, correo: user.correo },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.redirect(`${FRONTEND_URL}/admin/panel?token=${sessionToken}`);

  } catch (err) {
    console.error(err);
    res.status(500).send('Error');
  }
});

// ─── ME ─────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ─── CRUD USUARIOS ──────────────────────────────────────
app.get('/api/usuarios', requireAuth, async (req, res) => {
  const result = await pool.query(`SELECT * FROM usuarios`);
  res.json(result.rows);
});

app.post('/api/usuarios', requireAuth, async (req, res) => {
  const { nombre, apellidos, correo, contrasena } = req.body;

  const hash = await bcrypt.hash(contrasena, 10);

  const result = await pool.query(
    `INSERT INTO usuarios (nombre, apellidos, correo, contrasena)
     VALUES ($1,$2,$3,$4) RETURNING *`,
    [nombre, apellidos, correo, hash]
  );

  res.json(result.rows[0]);
});

app.delete('/api/usuarios/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]);
  res.json({ message: 'Eliminado' });
});

// ─── EXPORT PARA VERCEL ─────────────────────────────────
module.exports = app;