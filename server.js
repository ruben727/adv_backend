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
const FRONTEND_URL = "https://frontend-nine-delta-33.vercel.app/";

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
      from: `"Agua de Vida" <${EMAIL_USER}>`,
      to: user.correo,
      subject: '🔐 Confirma tu inicio de sesión - Agua de Vida',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin:0;padding:0;font-family:'Segoe UI',Roboto,'Helvetica Neue',sans-serif;background:#f0f4f8;">
          <div style="max-width:560px;margin:40px auto;background:#ffffff;border-radius:24px;overflow:hidden;box-shadow:0 20px 35px -10px rgba(0,0,0,0.1);">
            
            <div style="background:linear-gradient(135deg,#0f2b3d,#1a4d6f);padding:32px 24px;text-align:center;">
              <h1 style="margin:0;font-size:28px;font-weight:700;color:#ffffff;letter-spacing:-0.5px;">🌊 Agua de Vida</h1>
              <p style="margin:12px 0 0;font-size:15px;color:#b8deff;font-weight:500;">Panel Administrativo</p>
            </div>
            
            <div style="padding:40px 32px;">
              <h2 style="margin:0 0 8px;font-size:24px;font-weight:600;color:#1a2c3e;">Hola, ${user.nombre} ${user.apellidos || ''} 👋</h2>
              <p style="color:#5a6e7c;font-size:16px;line-height:1.5;margin-bottom:28px;">
                Recibimos una solicitud de inicio de sesión para tu cuenta. 
                Confirma tu identidad haciendo clic en el botón de abajo.
              </p>
              
              <div style="background:#f8fafc;border-radius:16px;padding:20px;margin:24px 0;border:1px solid #e2e8f0;">
                <p style="margin:0 0 12px;font-size:14px;color:#4a5b6e;">
                  ⏱️ <strong>Este enlace expira en 15 minutos</strong>
                </p>
                <p style="margin:0;font-size:13px;color:#6c7e91;">
                  📧 ${user.correo}
                </p>
              </div>
              
              <a href="${confirmLink}" 
                 style="display:block;background:linear-gradient(135deg,#1a5d8c,#0f3b56);color:#ffffff;
                        text-align:center;padding:16px 24px;border-radius:12px;text-decoration:none;
                        font-weight:600;font-size:16px;margin:32px 0 24px;transition:all 0.2s;
                        box-shadow:0 4px 12px rgba(26,93,140,0.3);">
                🔐 Confirmar inicio de sesión
              </a>
              
              <p style="color:#7e8e9e;font-size:14px;line-height:1.5;margin-top:24px;border-top:1px solid #e9edf2;padding-top:24px;">
                ⚠️ Si no solicitaste este acceso, puedes ignorar este mensaje. 
                Tu cuenta permanece segura y nadie podrá acceder sin este enlace.
              </p>
            </div>
            
            <div style="background:#f8fafc;padding:20px 32px;text-align:center;border-top:1px solid #e2e8f0;">
              <p style="margin:0;font-size:12px;color:#8a99aa;">
                © 2025 Agua de Vida - Panel Administrativo
              </p>
              <p style="margin:8px 0 0;font-size:11px;color:#a0aec0;">
                Este es un correo automático, por favor no responder.
              </p>
            </div>
          </div>
        </body>
        </html>
      `
    });

    res.json({ message: 'Correo enviado. Revisa tu bandeja de entrada.' });

  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ message: 'Error interno del servidor.' });
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
      return res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>Enlace inválido</title></head>
        <body style="font-family:sans-serif;text-align:center;padding:50px;">
          <h2>🔒 Enlace inválido o expirado</h2>
          <p>El enlace de confirmación ha expirado o ya fue utilizado.</p>
          <p>Por favor, solicita un nuevo inicio de sesión.</p>
        </body>
        </html>
      `);
    }

    const user = result.rows[0];

    await pool.query(
      `UPDATE usuarios 
       SET confirm_token = NULL, confirm_token_expires = NULL 
       WHERE id = $1`,
      [user.id]
    );

    const sessionToken = jwt.sign(
      { id: user.id, correo: user.correo, nombre: user.nombre },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.redirect(`${FRONTEND_URL}/admin/panel?token=${sessionToken}`);

  } catch (err) {
    console.error('Error en confirmación:', err);
    res.status(500).send('Error interno del servidor');
  }
});

// ─── ME ─────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ─── CRUD USUARIOS (SIN AUTH) ────────────────────────────
app.get('/api/usuarios', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, nombre, apellidos, correo, activo, creado_en FROM usuarios ORDER BY id`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener usuarios.' });
  }
});

app.post('/api/usuarios', async (req, res) => {
  const { nombre, apellidos, correo, contrasena } = req.body;

  if (!nombre || !correo || !contrasena) {
    return res.status(400).json({ message: 'Faltan campos obligatorios.' });
  }

  try {
    const hash = await bcrypt.hash(contrasena, 10);

    const result = await pool.query(
      `INSERT INTO usuarios (nombre, apellidos, correo, contrasena)
       VALUES ($1, $2, $3, $4) RETURNING id, nombre, apellidos, correo, activo, creado_en`,
      [nombre, apellidos || null, correo, hash]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    if (err.code === '23505') {
      return res.status(409).json({ message: 'El correo ya está registrado.' });
    }
    res.status(500).json({ message: 'Error al crear usuario.' });
  }
});

app.delete('/api/usuarios/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]);
    res.json({ message: 'Usuario eliminado correctamente.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al eliminar usuario.' });
  }
});

// ─── HEALTH CHECK ───────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ─── EXPORT PARA VERCEL ─────────────────────────────────
module.exports = app;