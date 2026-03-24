// server.js
// Instala: npm install express pg bcrypt nodemailer jsonwebtoken dotenv cors

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors({ origin: 'http://localhost:4200' }));

// ─── Conexión a Supabase / PostgreSQL ────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Error conectando a la base de datos:', err.message);
  } else {
    console.log('✅ Conexión a Supabase/PostgreSQL exitosa');
    release();
  }
});

// ─── Configuración de correo (Nodemailer + Gmail) ─────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

transporter.verify((err, success) => {
  if (err) {
    console.error('❌ Error configurando correo:', err.message);
  } else {
    console.log('✅ Configuración de correo exitosa');
  }
});

// ─── Utilidades ───────────────────────────────────────────────────────────────
function generateConfirmToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ─── Middleware de autenticación ──────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No autorizado.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido.' });
    req.user = user;
    next();
  });
}

// ─── POST /api/login ──────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Correo y contraseña son requeridos.' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE correo = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales incorrectas.' });
    }

    const user = result.rows[0];

    const passwordMatch = await bcrypt.compare(password, user.contrasena);
    if (!passwordMatch) {
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

    const confirmLink = `${process.env.BACKEND_URL}/api/confirm/${confirmToken}`;

    await transporter.sendMail({
      from: `"Panel Admin" <${process.env.EMAIL_USER}>`,
      to: user.correo,
      subject: 'Confirma tu inicio de sesión',
      html: `
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f9fafb;border-radius:12px;">
          <h2 style="color:#1f2937;margin-bottom:8px;">Hola, ${user.nombre} 👋</h2>
          <p style="color:#6b7280;margin-bottom:24px;">
            Recibimos una solicitud de inicio de sesión. Haz clic en el botón para confirmar tu acceso.
            Este enlace expira en <strong>15 minutos</strong>.
          </p>
          <a href="${confirmLink}" 
             style="display:inline-block;background:linear-gradient(135deg,#0f2744,#1e6aa8);color:#fff;
                    padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:15px;">
            Confirmar inicio de sesión
          </a>
          <p style="color:#9ca3af;font-size:12px;margin-top:24px;">
            Si no solicitaste esto, ignora este correo. Tu cuenta sigue segura.
          </p>
        </div>
      `
    });

    return res.json({ message: 'Correo de confirmación enviado.' });

  } catch (err) {
    console.error('Error en /api/login:', err);
    return res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

// ─── GET /api/confirm/:token ──────────────────────────────────────────────────
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
        <h2 style="font-family:sans-serif;text-align:center;margin-top:60px;color:#ef4444;">
          El enlace es inválido o ha expirado.
        </h2>
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
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    return res.redirect(`${process.env.FRONTEND_URL}/admin/panel?token=${sessionToken}`);

  } catch (err) {
    console.error('Error en /api/confirm:', err);
    return res.status(500).send('Error interno.');
  }
});

// ─── GET /api/me ──────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  USUARIOS — CRUD
// ═══════════════════════════════════════════════════════════════════════════════

// ─── GET /api/usuarios — Listar todos ─────────────────────────────────────────
app.get('/api/usuarios', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, nombre, apellidos, correo, activo, creado_en
       FROM usuarios
       ORDER BY creado_en DESC`
    );
    return res.json({ usuarios: result.rows });
  } catch (err) {
    console.error('Error en GET /api/usuarios:', err);
    return res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

// ─── POST /api/usuarios — Crear nuevo usuario ─────────────────────────────────
app.post('/api/usuarios', requireAuth, async (req, res) => {
  const { nombre, apellidos, correo, contrasena } = req.body;

  if (!nombre || !apellidos || !correo || !contrasena) {
    return res.status(400).json({ message: 'Todos los campos son requeridos.' });
  }

  // Validar formato de correo
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(correo)) {
    return res.status(400).json({ message: 'El formato del correo no es válido.' });
  }

  // Validar longitud de contraseña
  if (contrasena.length < 8) {
    return res.status(400).json({ message: 'La contraseña debe tener al menos 8 caracteres.' });
  }

  try {
    // Verificar si el correo ya existe
    const existente = await pool.query(
      'SELECT id FROM usuarios WHERE correo = $1',
      [correo]
    );

    if (existente.rows.length > 0) {
      return res.status(409).json({ message: 'Ya existe un usuario con ese correo.' });
    }

    // Hashear contraseña
    const hash = await bcrypt.hash(contrasena, 10);

    // Insertar usuario
    const result = await pool.query(
      `INSERT INTO usuarios (nombre, apellidos, correo, contrasena)
       VALUES ($1, $2, $3, $4)
       RETURNING id, nombre, apellidos, correo, activo, creado_en`,
      [nombre.trim(), apellidos.trim(), correo.toLowerCase().trim(), hash]
    );

    return res.status(201).json({
      message: 'Usuario creado exitosamente.',
      usuario: result.rows[0]
    });

  } catch (err) {
    console.error('Error en POST /api/usuarios:', err);
    return res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

// ─── PATCH /api/usuarios/:id/activo — Activar / desactivar ───────────────────
app.patch('/api/usuarios/:id/activo', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { activo } = req.body;

  if (typeof activo !== 'boolean') {
    return res.status(400).json({ message: 'El campo activo debe ser true o false.' });
  }

  try {
    const result = await pool.query(
      `UPDATE usuarios SET activo = $1 WHERE id = $2
       RETURNING id, nombre, apellidos, correo, activo`,
      [activo, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    return res.json({ message: 'Usuario actualizado.', usuario: result.rows[0] });

  } catch (err) {
    console.error('Error en PATCH /api/usuarios/:id/activo:', err);
    return res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

// ─── DELETE /api/usuarios/:id — Eliminar usuario ──────────────────────────────
app.delete('/api/usuarios/:id', requireAuth, async (req, res) => {
  const { id } = req.params;

  // No permitir que el admin se elimine a si mismo
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ message: 'No puedes eliminar tu propia cuenta.' });
  }

  try {
    const result = await pool.query(
      'DELETE FROM usuarios WHERE id = $1 RETURNING id, nombre',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    return res.json({ message: `Usuario ${result.rows[0].nombre} eliminado.` });

  } catch (err) {
    console.error('Error en DELETE /api/usuarios/:id:', err);
    return res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

// ─── Iniciar servidor ─────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en http://localhost:${PORT}`);
});