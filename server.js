/**
 * EncomPR — Sistema de Gestión de Notas de Prensa
 * Servidor HTTP puro con Node.js (sin dependencias externas)
 * Encom: OWN Valencia · Valencia Game City
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

// ─── Config ───────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const PORTAL_URL = process.env.PORTAL_URL || 'https://tools.encom.es';
const httpsModule = require('https');

function ssoValidate(token) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(`${PORTAL_URL}/api/auth/sso/validate?token=${token}`);
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || 443,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      rejectUnauthorized: false,
      headers: { 'Accept': 'application/json' },
    };
    const r = httpsModule.request(options, (response) => {
      let data = '';
      response.on('data', chunk => data += chunk);
      response.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`SSO parse error: ${data.substring(0, 200)}`)); }
      });
    });
    r.on('error', reject);
    r.setTimeout(10000, () => { r.destroy(); reject(new Error('SSO timeout')); });
    r.end();
  });
}

// Ensure data dir exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ─── Helpers ──────────────────────────────────────────────
function readJSON(file) {
  const fp = path.join(DATA_DIR, file);
  if (!fs.existsSync(fp)) return [];
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); }
  catch { return []; }
}

function writeJSON(file, data) {
  fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2), 'utf8');
}

function readConfig(file) {
  const fp = path.join(DATA_DIR, file);
  if (!fs.existsSync(fp)) return {};
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); }
  catch { return {}; }
}

function uuid() {
  return crypto.randomUUID();
}

function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function now() {
  return new Date().toISOString();
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 10e6) { req.destroy(); reject(new Error('Body too large')); }
    });
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function json(res, data, status = 200) {
  cors(res);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

function error(res, msg, status = 400) {
  json(res, { error: msg }, status);
}

function getAuth(req) {
  const h = req.headers.authorization;
  // Also accept token via query param for download links
  const urlToken = new URL(req.url, `http://${req.headers.host || 'localhost'}`).searchParams.get('_token');
  const token = h ? h.replace('Bearer ', '') : urlToken;
  if (!token) return null;
  const sessions = readJSON('sessions.json');
  const s = sessions.find(s => s.token === token);
  if (!s) return null;
  const users = readJSON('users.json');
  return users.find(u => u.id === s.userId) || null;
}

function requireAuth(req, res) {
  const user = getAuth(req);
  if (!user) { error(res, 'No autorizado', 401); return null; }
  return user;
}

function requireAdmin(req, res) {
  const user = requireAuth(req, res);
  if (user && user.role !== 'admin') { error(res, 'Acceso denegado', 403); return null; }
  return user;
}

// ─── MIME types ───────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

// ─── Router ───────────────────────────────────────────────
function matchRoute(method, urlPath, routeMethod, routePattern) {
  if (method !== routeMethod) return null;
  const routeParts = routePattern.split('/');
  const urlParts = urlPath.split('/');
  if (routeParts.length !== urlParts.length) return null;
  const params = {};
  for (let i = 0; i < routeParts.length; i++) {
    if (routeParts[i].indexOf(':') === 0) {
      params[routeParts[i].slice(1)] = urlParts[i];
    } else if (routeParts[i] !== urlParts[i]) {
      return null;
    }
  }
  return params;
}

// ─── Routes ───────────────────────────────────────────────
const routes = [];
function route(method, pattern, handler) {
  routes.push({ method, pattern, handler });
}

// ── AUTH ──
route('POST', '/api/auth/login', async (req, res) => {
  const { email, password } = await parseBody(req);
  if (!email || !password) return error(res, 'Email y contraseña requeridos');
  const users = readJSON('users.json');
  const user = users.find(u => u.email === email.toLowerCase().trim());
  if (!user) return error(res, 'Credenciales inválidas', 401);
  if (user.passwordHash !== hashPassword(password)) return error(res, 'Credenciales inválidas', 401);
  const token = generateToken();
  const sessions = readJSON('sessions.json');
  sessions.push({ token, userId: user.id, createdAt: now() });
  writeJSON('sessions.json', sessions);
  json(res, { token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

route('POST', '/api/auth/logout', async (req, res) => {
  const h = req.headers.authorization;
  if (h) {
    const token = h.replace('Bearer ', '');
    let sessions = readJSON('sessions.json');
    sessions = sessions.filter(s => s.token !== token);
    writeJSON('sessions.json', sessions);
  }
  json(res, { ok: true });
});

route('GET', '/api/auth/me', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  json(res, { id: user.id, name: user.name, email: user.email, role: user.role });
});

// ── USERS ──
route('GET', '/api/users', async (req, res) => {
  const user = requireAdmin(req, res);
  if (!user) return;
  const users = readJSON('users.json').map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, createdAt: u.createdAt }));
  json(res, users);
});

route('POST', '/api/users', async (req, res) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  const { name, email, password, role } = await parseBody(req);
  if (!name || !email || !password) return error(res, 'Nombre, email y contraseña requeridos');
  const users = readJSON('users.json');
  if (users.find(u => u.email === email.toLowerCase().trim())) return error(res, 'Email ya registrado');
  const newUser = { id: uuid(), name, email: email.toLowerCase().trim(), passwordHash: hashPassword(password), role: role || 'editor', createdAt: now() };
  users.push(newUser);
  writeJSON('users.json', users);
  json(res, { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role }, 201);
});

route('DELETE', '/api/users/:id', async (req, res, params) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  let users = readJSON('users.json');
  users = users.filter(u => u.id !== params.id);
  writeJSON('users.json', users);
  json(res, { ok: true });
});

// ── NOTAS DE PRENSA ──
route('GET', '/api/notas', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const notas = readJSON('notas.json');
  json(res, notas.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt)));
});

route('GET', '/api/notas/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const notas = readJSON('notas.json');
  const nota = notas.find(n => n.id === params.id);
  if (!nota) return error(res, 'Nota no encontrada', 404);
  json(res, nota);
});

route('POST', '/api/notas', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const nota = {
    id: uuid(),
    proyecto: body.proyecto || 'Encom',
    objetivo: body.objetivo || '',
    noticiaPrincipal: body.noticiaPrincipal || '',
    titular: body.titular || '',
    subtitulo: body.subtitulo || '',
    cuerpo: body.cuerpo || '',
    datosClaveRaw: body.datosClaveRaw || '',
    citas: body.citas || '',
    entidades: body.entidades || '',
    exclusiones: body.exclusiones || '',
    contactoPrensa: body.contactoPrensa || '',
    materialesAdjuntos: body.materialesAdjuntos || '',
    notaEjemplo: body.notaEjemplo || '',
    plantilla: body.plantilla || '',
    estado: body.estado || 'borrador',
    autorId: user.id,
    autorNombre: user.name,
    validaciones: [],
    publicaciones: [],
    envios: [],
    createdAt: now(),
    updatedAt: now(),
  };
  const notas = readJSON('notas.json');
  notas.push(nota);
  writeJSON('notas.json', notas);
  json(res, nota, 201);
});

route('PUT', '/api/notas/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const notas = readJSON('notas.json');
  const idx = notas.findIndex(n => n.id === params.id);
  if (idx === -1) return error(res, 'Nota no encontrada', 404);
  const allowed = ['proyecto', 'objetivo', 'noticiaPrincipal', 'titular', 'subtitulo', 'cuerpo', 'datosClaveRaw', 'citas', 'entidades', 'exclusiones', 'contactoPrensa', 'materialesAdjuntos', 'notaEjemplo', 'plantilla', 'estado'];
  for (const key of allowed) {
    if (body[key] !== undefined) notas[idx][key] = body[key];
  }
  notas[idx].updatedAt = now();
  writeJSON('notas.json', notas);
  json(res, notas[idx]);
});

route('DELETE', '/api/notas/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  let notas = readJSON('notas.json');
  notas = notas.filter(n => n.id !== params.id);
  writeJSON('notas.json', notas);
  json(res, { ok: true });
});

// ── VALIDACIÓN EXTERNA ──
route('POST', '/api/notas/:id/validacion-link', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const notas = readJSON('notas.json');
  const idx = notas.findIndex(n => n.id === params.id);
  if (idx === -1) return error(res, 'Nota no encontrada', 404);
  const linkToken = generateToken().slice(0, 16);
  let links = readJSON('validation_links.json');
  links.push({ token: linkToken, notaId: params.id, createdBy: user.id, createdAt: now(), active: true });
  writeJSON('validation_links.json', links);
  notas[idx].estado = 'en_validacion';
  notas[idx].updatedAt = now();
  writeJSON('notas.json', notas);
  json(res, { link: `/validar/${linkToken}`, token: linkToken });
});

route('GET', '/api/validar/:token', async (req, res, params) => {
  const links = readJSON('validation_links.json');
  const link = links.find(l => l.token === params.token && l.active);
  if (!link) return error(res, 'Link inválido o expirado', 404);
  const notas = readJSON('notas.json');
  const nota = notas.find(n => n.id === link.notaId);
  if (!nota) return error(res, 'Nota no encontrada', 404);
  json(res, { nota: { id: nota.id, proyecto: nota.proyecto, titular: nota.titular, subtitulo: nota.subtitulo, cuerpo: nota.cuerpo, datosClaveRaw: nota.datosClaveRaw, citas: nota.citas, contactoPrensa: nota.contactoPrensa, materialesAdjuntos: nota.materialesAdjuntos, estado: nota.estado, validaciones: nota.validaciones } });
});

route('POST', '/api/validar/:token', async (req, res, params) => {
  const links = readJSON('validation_links.json');
  const link = links.find(l => l.token === params.token && l.active);
  if (!link) return error(res, 'Link inválido o expirado', 404);
  const body = await parseBody(req);
  if (!body.accion || !['aprobar', 'cambios', 'rechazar'].includes(body.accion)) return error(res, 'Acción inválida');
  const notas = readJSON('notas.json');
  const idx = notas.findIndex(n => n.id === link.notaId);
  if (idx === -1) return error(res, 'Nota no encontrada', 404);
  const validacion = { id: uuid(), accion: body.accion, comentario: body.comentario || '', validadorNombre: body.nombre || 'Validador externo', fecha: now() };
  notas[idx].validaciones.push(validacion);
  if (body.accion === 'aprobar') notas[idx].estado = 'validada';
  else if (body.accion === 'rechazar') notas[idx].estado = 'borrador';
  notas[idx].updatedAt = now();
  writeJSON('notas.json', notas);
  // Add notification
  const notifs = readJSON('notifications.json');
  notifs.push({ id: uuid(), type: 'validacion', notaId: link.notaId, message: `Validación: ${body.accion} por ${validacion.validadorNombre}`, read: false, createdAt: now() });
  writeJSON('notifications.json', notifs);
  json(res, { ok: true, estado: notas[idx].estado });
});

// ── PUBLICACIONES ──
route('POST', '/api/notas/:id/publicaciones', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const notas = readJSON('notas.json');
  const idx = notas.findIndex(n => n.id === params.id);
  if (idx === -1) return error(res, 'Nota no encontrada', 404);
  const pub = { id: uuid(), medio: body.medio || '', url: body.url || '', fecha: body.fecha || now(), registradoPor: user.name };
  notas[idx].publicaciones.push(pub);
  if (notas[idx].estado !== 'publicada') notas[idx].estado = 'publicada';
  notas[idx].updatedAt = now();
  writeJSON('notas.json', notas);
  json(res, pub, 201);
});

// ── ENVÍOS ──
route('POST', '/api/notas/:id/envios', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const notas = readJSON('notas.json');
  const idx = notas.findIndex(n => n.id === params.id);
  if (idx === -1) return error(res, 'Nota no encontrada', 404);
  const envio = { id: uuid(), mediosIds: body.mediosIds || [], fecha: now(), enviadoPor: user.name, via: body.via || 'manual' };
  notas[idx].envios.push(envio);
  if (notas[idx].estado === 'validada') notas[idx].estado = 'enviada';
  notas[idx].updatedAt = now();
  writeJSON('notas.json', notas);
  // Update media contact history
  const medios = readJSON('medios.json');
  for (const mid of envio.mediosIds) {
    const m = medios.find(x => x.id === mid);
    if (m) {
      if (!m.historialEnvios) m.historialEnvios = [];
      m.historialEnvios.push({ notaId: params.id, fecha: now() });
    }
  }
  writeJSON('medios.json', medios);
  json(res, envio, 201);
});

// ── CONTACTOS DE MEDIOS ──
route('GET', '/api/medios', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const medios = readJSON('medios.json');
  json(res, medios);
});

route('GET', '/api/medios/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const medios = readJSON('medios.json');
  const medio = medios.find(m => m.id === params.id);
  if (!medio) return error(res, 'Contacto no encontrado', 404);
  json(res, medio);
});

route('POST', '/api/medios', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const medio = {
    id: uuid(),
    nombre: body.nombre || '',
    email: body.email || '',
    medio: body.medio || '',
    cargo: body.cargo || '',
    tematicas: body.tematicas || [],
    region: body.region || 'Nacional',
    telefono: body.telefono || '',
    notas: body.notas || '',
    historialEnvios: [],
    publicaciones: 0,
    tasaPublicacion: 0,
    createdAt: now(),
    updatedAt: now(),
  };
  const medios = readJSON('medios.json');
  medios.push(medio);
  writeJSON('medios.json', medios);
  json(res, medio, 201);
});

route('PUT', '/api/medios/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const medios = readJSON('medios.json');
  const idx = medios.findIndex(m => m.id === params.id);
  if (idx === -1) return error(res, 'Contacto no encontrado', 404);
  const allowed = ['nombre', 'email', 'medio', 'cargo', 'tematicas', 'region', 'telefono', 'notas', 'publicaciones', 'tasaPublicacion'];
  for (const key of allowed) {
    if (body[key] !== undefined) medios[idx][key] = body[key];
  }
  medios[idx].updatedAt = now();
  writeJSON('medios.json', medios);
  json(res, medios[idx]);
});

route('DELETE', '/api/medios/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  let medios = readJSON('medios.json');
  medios = medios.filter(m => m.id !== params.id);
  writeJSON('medios.json', medios);
  json(res, { ok: true });
});

// Suggest media contacts based on tematica + region
route('POST', '/api/medios/sugerir', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const { tematicas, region } = body;
  const medios = readJSON('medios.json');
  let filtered = medios;
  if (tematicas && tematicas.length > 0) {
    filtered = filtered.filter(m => m.tematicas && m.tematicas.some(t => tematicas.includes(t)));
  }
  if (region) {
    filtered = filtered.filter(m => m.region === region || m.region === 'Nacional' || m.region === 'Internacional');
  }
  // Sort by publication rate desc
  filtered.sort((a, b) => (b.tasaPublicacion || 0) - (a.tasaPublicacion || 0));
  json(res, filtered);
});

// Import CSV medios
route('POST', '/api/medios/importar-csv', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  if (!body.csv) return error(res, 'CSV requerido');
  const lines = body.csv.split('\n').filter(l => l.trim());
  if (lines.length < 2) return error(res, 'CSV vacío o sin datos');
  const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
  const medios = readJSON('medios.json');
  let imported = 0;
  for (let i = 1; i < lines.length; i++) {
    const vals = lines[i].split(',').map(v => v.trim());
    const obj = {};
    headers.forEach((h, idx) => { obj[h] = vals[idx] || ''; });
    const medio = {
      id: uuid(),
      nombre: obj.nombre || obj.name || '',
      email: obj.email || '',
      medio: obj.medio || obj.media || '',
      cargo: obj.cargo || obj.position || '',
      tematicas: (obj.tematicas || obj.tematica || '').split(';').map(t => t.trim()).filter(Boolean),
      region: obj.region || 'Nacional',
      telefono: obj.telefono || obj.phone || '',
      notas: obj.notas || '',
      historialEnvios: [],
      publicaciones: 0,
      tasaPublicacion: 0,
      createdAt: now(),
      updatedAt: now(),
    };
    if (medio.nombre || medio.email) {
      medios.push(medio);
      imported++;
    }
  }
  writeJSON('medios.json', medios);
  json(res, { imported, total: medios.length });
});

// Export medios as CSV
route('POST', '/api/medios/exportar-csv', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  let medios = readJSON('medios.json');
  // Optional filters
  if (body.tematicas && body.tematicas.length > 0) {
    medios = medios.filter(m => m.tematicas && m.tematicas.some(t => body.tematicas.includes(t)));
  }
  if (body.region) {
    medios = medios.filter(m => m.region === body.region);
  }
  const header = 'Email Address,First Name,Last Name,Tags';
  const rows = medios.map(m => {
    const parts = (m.nombre || '').split(' ');
    const first = parts[0] || '';
    const last = parts.slice(1).join(' ') || '';
    const tags = [m.medio, m.region, ...(m.tematicas || [])].filter(Boolean).join(';');
    return `${m.email},${first},${last},${tags}`;
  });
  cors(res);
  res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename=medios_export.csv' });
  res.end([header, ...rows].join('\n'));
});

// ── MAILCHIMP ──
function mcCall(method, path, data) {
  return new Promise((resolve, reject) => {
    const config = readConfig('mailchimp_config.json');
    if (!config.apiKey) return reject(new Error('Mailchimp no configurado'));
    const dc = config.serverPrefix || 'us1';
    const https = require('https');
    const postData = data ? JSON.stringify(data) : '';
    const options = {
      hostname: `${dc}.api.mailchimp.com`, path: `/3.0${path}`, method,
      headers: { 'Content-Type': 'application/json', 'Authorization': `Basic ${Buffer.from('x:' + config.apiKey).toString('base64')}` }
    };
    if (postData) options.headers['Content-Length'] = Buffer.byteLength(postData);
    const req = https.request(options, (r) => {
      let body = '';
      r.on('data', d => body += d);
      r.on('end', () => {
        try { const j = JSON.parse(body); if (r.statusCode >= 400) { reject(new Error(j.detail || j.title || 'Error Mailchimp')); } else resolve(j); }
        catch { resolve({ raw: body }); }
      });
    });
    req.on('error', reject);
    if (postData) req.write(postData);
    req.end();
  });
}

function notaToEmailHtml(nota) {
  const fecha = new Date(nota.updatedAt || nota.createdAt).toLocaleDateString('es-ES', { day: 'numeric', month: 'long', year: 'numeric' });
  const bodyHtml = (nota.cuerpo || '').split(/\n\n+/).filter(p => p.trim()).map(p =>
    `<p style="font-family:Arial,sans-serif;font-size:15px;color:#333;line-height:1.7;margin:0 0 16px 0">${p.replace(/\n/g, '<br>')}</p>`
  ).join('');
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:24px 0">
<tr><td align="center">
<table width="640" cellpadding="0" cellspacing="0" style="max-width:640px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08)">
  <!-- Header -->
  <tr><td style="background:#1a56db;padding:28px 40px">
    <table width="100%"><tr>
      <td style="font-family:Arial,sans-serif;font-size:22px;font-weight:700;color:#fff;letter-spacing:1px">ENCOM</td>
      <td align="right" style="font-family:Arial,sans-serif;font-size:12px;color:rgba(255,255,255,0.8)">NOTA DE PRENSA</td>
    </tr></table>
  </td></tr>
  <!-- Project + Date -->
  <tr><td style="padding:24px 40px 0">
    <table width="100%"><tr>
      <td style="font-family:Arial,sans-serif;font-size:12px;color:#1a56db;font-weight:600;text-transform:uppercase;letter-spacing:1px">${nota.proyecto || 'Encom'}</td>
      <td align="right" style="font-family:Arial,sans-serif;font-size:12px;color:#999">Valencia, ${fecha}</td>
    </tr></table>
  </td></tr>
  <!-- Titular -->
  <tr><td style="padding:20px 40px 8px">
    <h1 style="font-family:Georgia,serif;font-size:28px;line-height:1.25;color:#111;margin:0;font-weight:700">${nota.titular || 'Sin titular'}</h1>
  </td></tr>
  ${nota.subtitulo ? `<!-- Subtitulo -->
  <tr><td style="padding:0 40px 16px">
    <p style="font-family:Georgia,serif;font-size:17px;color:#555;line-height:1.4;margin:0">${nota.subtitulo}</p>
  </td></tr>` : ''}
  <!-- Separator -->
  <tr><td style="padding:0 40px"><hr style="border:none;border-top:1px solid #e5e7eb;margin:8px 0 20px"></td></tr>
  <!-- Body -->
  <tr><td style="padding:0 40px">${bodyHtml}</td></tr>
  <!-- Footer -->
  <tr><td style="padding:24px 40px 0"><hr style="border:none;border-top:2px solid #1a56db;margin:0 0 16px"></td></tr>
  <tr><td style="padding:0 40px 8px">
    <p style="font-family:Arial,sans-serif;font-size:11px;color:#1a56db;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin:0">Para m\u00e1s informaci\u00f3n</p>
  </td></tr>
  <tr><td style="padding:0 40px 8px">
    <p style="font-family:Arial,sans-serif;font-size:13px;color:#333;line-height:1.5;margin:0">${nota.contactoPrensa || 'prensa@encom.es'}</p>
  </td></tr>
  ${nota.materialesAdjuntos ? `<tr><td style="padding:0 40px 8px"><p style="font-family:Arial,sans-serif;font-size:12px;color:#666;margin:0">Materiales: <a href="${nota.materialesAdjuntos}" style="color:#1a56db">${nota.materialesAdjuntos}</a></p></td></tr>` : ''}
  <tr><td style="padding:16px 40px 24px">
    <p style="font-family:Arial,sans-serif;font-size:11px;color:#aaa;margin:0;text-align:center">Encom \u00b7 Gesti\u00f3n de Eventos \u00b7 Valencia</p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`;
}

route('GET', '/api/mailchimp/config', async (req, res) => {
  const user = requireAdmin(req, res);
  if (!user) return;
  const config = readConfig('mailchimp_config.json');
  json(res, { configured: !!config.apiKey, serverPrefix: config.serverPrefix || '' });
});

route('POST', '/api/mailchimp/config', async (req, res) => {
  const user = requireAdmin(req, res);
  if (!user) return;
  const body = await parseBody(req);
  writeJSON('mailchimp_config.json', { apiKey: body.apiKey || '', serverPrefix: body.serverPrefix || 'us1', defaultFromName: body.defaultFromName || 'Encom', defaultFromEmail: body.defaultFromEmail || 'prensa@encom.es', defaultReplyTo: body.defaultReplyTo || 'javier@encom.es' });
  json(res, { ok: true });
});

// Get all Mailchimp lists
route('GET', '/api/mailchimp/listas', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  try {
    const data = await mcCall('GET', '/lists?count=100');
    const listas = (data.lists || []).map(l => ({ id: l.id, name: l.name, memberCount: l.stats?.member_count || 0 }));
    json(res, listas);
  } catch (e) { error(res, e.message, 500); }
});

// Create a new list
route('POST', '/api/mailchimp/crear-lista', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const config = readConfig('mailchimp_config.json');
  try {
    const data = await mcCall('POST', '/lists', {
      name: body.nombre || 'Lista EncomPR',
      contact: { company: 'Encom', address1: 'Valencia', city: 'Valencia', state: 'VC', zip: '46001', country: 'ES' },
      permission_reminder: 'Recibe esta comunicaci\u00f3n por ser contacto de prensa de Encom',
      campaign_defaults: { from_name: config.defaultFromName || 'Encom', from_email: config.defaultFromEmail || 'prensa@encom.es', subject: 'Nota de prensa', language: 'es' },
      email_type_option: false
    });
    json(res, { id: data.id, name: data.name }, 201);
  } catch (e) { error(res, e.message, 500); }
});

// Sync contacts to a Mailchimp list
route('POST', '/api/mailchimp/sincronizar-contactos', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const { listId, contactIds } = body;
  if (!listId) return error(res, 'Lista requerida');
  const medios = readJSON('medios.json');
  const contacts = contactIds && contactIds.length > 0
    ? medios.filter(m => contactIds.includes(m.id))
    : medios;
  if (contacts.length === 0) return error(res, 'No hay contactos para sincronizar');
  let added = 0, errors_list = [];
  for (const c of contacts) {
    if (!c.email) continue;
    const parts = (c.nombre || '').split(' ');
    try {
      await mcCall('POST', `/lists/${listId}/members`, {
        email_address: c.email,
        status: 'subscribed',
        merge_fields: { FNAME: parts[0] || '', LNAME: parts.slice(1).join(' ') || '' },
        tags: [c.medio, c.region, ...(c.tematicas || [])].filter(Boolean)
      });
      added++;
    } catch (e) {
      if (e.message && e.message.includes('already a list member')) { added++; }
      else { errors_list.push({ email: c.email, error: e.message }); }
    }
  }
  json(res, { added, errors: errors_list, total: contacts.length });
});

// Get members of a list
route('GET', '/api/mailchimp/listas/:id/miembros', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  try {
    const data = await mcCall('GET', `/lists/${params.id}/members?count=200`);
    const members = (data.members || []).map(m => ({ email: m.email_address, name: `${m.merge_fields?.FNAME || ''} ${m.merge_fields?.LNAME || ''}`.trim(), status: m.status }));
    json(res, members);
  } catch (e) { error(res, e.message, 500); }
});

// Create campaign from a nota
route('POST', '/api/notas/:id/crear-campana', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const notas = readJSON('notas.json');
  const nota = notas.find(n => n.id === params.id);
  if (!nota) return error(res, 'Nota no encontrada', 404);
  const body = await parseBody(req);
  const { listId } = body;
  if (!listId) return error(res, 'Selecciona una lista de envío');
  const config = readConfig('mailchimp_config.json');
  try {
    // 1. Create campaign
    const campaign = await mcCall('POST', '/campaigns', {
      type: 'regular',
      recipients: { list_id: listId },
      settings: {
        subject_line: nota.titular || 'Nota de prensa - Encom',
        preview_text: nota.subtitulo || '',
        from_name: config.defaultFromName || 'Encom',
        reply_to: config.defaultReplyTo || config.defaultFromEmail || 'prensa@encom.es',
        title: `NP: ${(nota.titular || 'Sin titular').substring(0, 60)}`
      }
    });
    if (!campaign.id) return error(res, 'No se pudo crear la campaña', 500);
    // 2. Set HTML content
    const emailHtml = notaToEmailHtml(nota);
    await mcCall('PUT', `/campaigns/${campaign.id}/content`, { html: emailHtml });
    json(res, { campaignId: campaign.id, webId: campaign.web_id, archiveUrl: campaign.archive_url, status: 'created', message: 'Campaña creada. Revísala en Mailchimp antes de enviar.' });
  } catch (e) { error(res, 'Error creando campaña: ' + e.message, 500); }
});

// ── PLANTILLAS ──
route('GET', '/api/plantillas', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  json(res, readJSON('plantillas.json'));
});

route('POST', '/api/plantillas', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const plantilla = { id: uuid(), nombre: body.nombre || '', tipo: body.tipo || 'general', contenido: body.contenido || {}, createdAt: now() };
  const plantillas = readJSON('plantillas.json');
  plantillas.push(plantilla);
  writeJSON('plantillas.json', plantillas);
  json(res, plantilla, 201);
});

route('DELETE', '/api/plantillas/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  let plantillas = readJSON('plantillas.json');
  plantillas = plantillas.filter(p => p.id !== params.id);
  writeJSON('plantillas.json', plantillas);
  json(res, { ok: true });
});

// ── EXTRACCIÓN DOCX ──
route('POST', '/api/extraer-docx', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  if (!body.base64) return error(res, 'No se recibió el archivo');
  try {
    const zlib = require('zlib');
    const buf = Buffer.from(body.base64, 'base64');
    // .docx is a zip file. We look for word/document.xml inside it.
    // Minimal zip parser: find local file headers and extract document.xml
    let text = '';
    let offset = 0;
    while (offset < buf.length - 4) {
      // Local file header signature: 0x04034b50
      if (buf.readUInt32LE(offset) !== 0x04034b50) break;
      const compMethod = buf.readUInt16LE(offset + 8);
      const compSize = buf.readUInt32LE(offset + 18);
      const uncompSize = buf.readUInt32LE(offset + 22);
      const nameLen = buf.readUInt16LE(offset + 26);
      const extraLen = buf.readUInt16LE(offset + 28);
      const fileName = buf.toString('utf8', offset + 30, offset + 30 + nameLen);
      const dataStart = offset + 30 + nameLen + extraLen;
      const rawData = buf.slice(dataStart, dataStart + compSize);
      if (fileName === 'word/document.xml') {
        let xmlBuf;
        if (compMethod === 8) { // deflate
          xmlBuf = zlib.inflateRawSync(rawData);
        } else {
          xmlBuf = rawData;
        }
        const xml = xmlBuf.toString('utf8');
        // Extract text from <w:t> tags
        text = xml.replace(/<w:p[^>]*>/g, '\n').replace(/<[^>]+>/g, '').replace(/\n{3,}/g, '\n\n').trim();
        break;
      }
      offset = dataStart + compSize;
    }
    if (!text) return error(res, 'No se pudo extraer texto del docx. Asegúrate de que es un archivo .docx válido.');
    json(res, { text, chars: text.length });
  } catch (e) {
    error(res, 'Error al procesar el docx: ' + e.message, 500);
  }
});

// ── GENERACIÓN IA ──
route('POST', '/api/notas/generar-ia', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!ANTHROPIC_API_KEY) return error(res, 'API de IA no configurada. Añade ANTHROPIC_API_KEY en las variables de entorno.', 500);

  const body = await parseBody(req);
  const { proyecto, objetivo, noticiaPrincipal, datosClaveRaw, citas, entidades, exclusiones, contactoPrensa, materialesAdjuntos, notaEjemplo } = body;

  if (!noticiaPrincipal && !datosClaveRaw) return error(res, 'Necesito al menos la noticia principal o datos clave para generar la nota');

  const systemPrompt = `Eres el jefe de comunicación de Encom, una empresa líder en gestión de eventos en España. Tus eventos principales son OWN Valencia (festival de música) y Valencia Game City (evento gaming).

Tu trabajo es redactar notas de prensa profesionales, perfectas para enviar a medios de comunicación españoles.

Reglas de estilo:
- Tono profesional pero cercano, típico de comunicación corporativa española
- Titular: impactante, con dato concreto, máximo 120 caracteres
- Subtítulo: amplía el titular con contexto, máximo 200 caracteres
- Cuerpo: 6-8 párrafos bien desarrollados, extensos y con profundidad periodística
  - Párrafo 1: Lead informativo — Qué, cuándo, dónde, quién (lo esencial de la noticia, directo y claro)
  - Párrafo 2: Desarrollo de la noticia principal con más contexto y detalles
  - Párrafo 3: Detalles del programa, contenido o propuesta de valor
  - Párrafo 4: Novedades, datos diferenciadores, comparativa con ediciones anteriores si aplica
  - Párrafo 5: Cita del CEO o responsable (usa las citas proporcionadas, o genera una verosímil de Javi, CEO de Encom)
  - Párrafo 6: Contexto sectorial — posicionar el evento/noticia dentro del sector
  - Párrafo 7: Datos prácticos (entradas, precios, acceso, fechas, web)
  - Párrafo final: Sobre Encom — breve descripción corporativa (1-2 frases)
- Cada párrafo debe tener al menos 3-4 frases. No seas escueto, desarrolla las ideas
- Incluye los datos numéricos/cifras proporcionados de forma natural en el texto
- Nombra las entidades indicadas con el argumento especificado
- RESPETA ESTRICTAMENTE las exclusiones: lo que el usuario dice que NO debe aparecer, NO aparece
- NO uses formato markdown, solo texto plano con saltos de línea
- Escribe SIEMPRE en castellano`;

  const userPrompt = `Genera una nota de prensa profesional con estos datos:

PROYECTO/EVENTO: ${proyecto || 'Encom'}
OBJETIVO DE LA NOTA: ${objetivo || 'Generar cobertura mediática'}
NOTICIA PRINCIPAL: ${noticiaPrincipal || 'No especificada'}
DATOS CLAVE Y CIFRAS: ${datosClaveRaw || 'No proporcionados'}
CITAS TEXTUALES: ${citas || 'No proporcionadas, genera una verosímil del CEO'}
ENTIDADES A NOMBRAR: ${entidades || 'No especificadas'}
COSAS QUE NO DEBEN APARECER: ${exclusiones || 'Ninguna restricción especial'}
CONTACTO DE PRENSA: ${contactoPrensa || 'Departamento de Comunicación Encom — prensa@encom.es — 960 000 000'}
MATERIALES: ${materialesAdjuntos || 'No proporcionados'}
${notaEjemplo ? `\nNOTA DE REFERENCIA (imita el estilo y estructura de esta nota):\n${notaEjemplo}` : ''}

Responde EXCLUSIVAMENTE con un JSON válido (sin markdown, sin backticks) con esta estructura:
{"titular": "...", "subtitulo": "...", "cuerpo": "..."}

El cuerpo debe usar \\n\\n para separar párrafos. No incluyas nada más fuera del JSON.`;

  try {
    const https = require('https');
    const postData = JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4000,
      messages: [
        { role: 'user', content: userPrompt }
      ],
      system: systemPrompt,
    });

    const options = {
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(postData),
      }
    };

    const apiReq = https.request(options, (apiRes) => {
      let data = '';
      apiRes.on('data', d => data += d);
      apiRes.on('end', () => {
        try {
          const result = JSON.parse(data);
          if (result.error) {
            return error(res, `Error de IA: ${result.error.message}`, 500);
          }
          // Extract text from Claude response
          const text = result.content?.[0]?.text || '';
          // Parse the JSON from the response
          try {
            const nota = JSON.parse(text);
            json(res, {
              titular: nota.titular || '',
              subtitulo: nota.subtitulo || '',
              cuerpo: nota.cuerpo || '',
            });
          } catch {
            // If JSON parsing fails, try to extract from the text
            json(res, {
              titular: '',
              subtitulo: '',
              cuerpo: text,
              _raw: true,
              _note: 'No se pudo estructurar la respuesta. El texto completo está en cuerpo.'
            });
          }
        } catch (e) {
          error(res, 'Error procesando respuesta de IA: ' + e.message, 500);
        }
      });
    });
    apiReq.on('error', e => error(res, 'Error conectando con IA: ' + e.message, 500));
    apiReq.write(postData);
    apiReq.end();
  } catch (e) {
    error(res, 'Error interno IA: ' + e.message, 500);
  }
});

// ── REGENERAR CON FEEDBACK ──
route('POST', '/api/notas/regenerar-ia', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (!ANTHROPIC_API_KEY) return error(res, 'API de IA no configurada', 500);

  const body = await parseBody(req);
  const { titularActual, subtituloActual, cuerpoActual, feedback, proyecto } = body;

  if (!feedback) return error(res, 'Escribe qué quieres mejorar');

  const systemPrompt = `Eres el jefe de comunicación de Encom (eventos: OWN Valencia, Valencia Game City). Redactas notas de prensa profesionales para medios españoles.
Reglas: tono profesional pero cercano, texto plano sin markdown, siempre en castellano.`;

  const userPrompt = `Tengo esta nota de prensa ya generada:

TITULAR: ${titularActual || ''}
SUBTÍTULO: ${subtituloActual || ''}
CUERPO:
${cuerpoActual || ''}

El usuario quiere estos cambios:
"${feedback}"

Reescribe la nota aplicando exactamente ese feedback. Mantén lo que estaba bien y mejora lo que se pide.

Responde EXCLUSIVAMENTE con un JSON válido (sin markdown, sin backticks):
{"titular": "...", "subtitulo": "...", "cuerpo": "..."}

El cuerpo usa \\n\\n para separar párrafos. Nada más fuera del JSON.`;

  try {
    const https = require('https');
    const postData = JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 2000,
      messages: [{ role: 'user', content: userPrompt }],
      system: systemPrompt,
    });
    const options = {
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'Content-Length': Buffer.byteLength(postData) }
    };
    const apiReq = https.request(options, (apiRes) => {
      let data = '';
      apiRes.on('data', d => data += d);
      apiRes.on('end', () => {
        try {
          const result = JSON.parse(data);
          if (result.error) return error(res, `Error de IA: ${result.error.message}`, 500);
          const text = result.content?.[0]?.text || '';
          try {
            const nota = JSON.parse(text);
            json(res, { titular: nota.titular || '', subtitulo: nota.subtitulo || '', cuerpo: nota.cuerpo || '' });
          } catch {
            json(res, { titular: '', subtitulo: '', cuerpo: text, _raw: true });
          }
        } catch (e) { error(res, 'Error procesando respuesta: ' + e.message, 500); }
      });
    });
    apiReq.on('error', e => error(res, 'Error conectando con IA: ' + e.message, 500));
    apiReq.write(postData);
    apiReq.end();
  } catch (e) { error(res, 'Error interno IA: ' + e.message, 500); }
});

// ── EXPORTAR NOTA COMO DOCX ──
route('GET', '/api/notas/:id/exportar-docx', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const notas = readJSON('notas.json');
  const nota = notas.find(n => n.id === params.id);
  if (!nota) return error(res, 'Nota no encontrada', 404);

  try {
    const docxLib = require('docx');
    const { Document, Packer, Paragraph, TextRun, AlignmentType, BorderStyle, HeadingLevel } = docxLib;

    const bodyParagraphs = (nota.cuerpo || '').split(/\n\n+/).filter(p => p.trim());
    const fecha = new Date(nota.updatedAt || nota.createdAt).toLocaleDateString('es-ES', { day: 'numeric', month: 'long', year: 'numeric' });
    const children = [];

    // ── HEADER ──
    children.push(new Paragraph({ alignment: AlignmentType.RIGHT, spacing: { after: 80 },
      children: [new TextRun({ text: 'ENCOM', font: 'Arial', size: 28, bold: true, color: '1a56db' })] }));
    if (nota.proyecto) {
      children.push(new Paragraph({ alignment: AlignmentType.RIGHT, spacing: { after: 200 },
        children: [new TextRun({ text: nota.proyecto, font: 'Arial', size: 20, color: '666666' })] }));
    }

    // Separator
    children.push(new Paragraph({ spacing: { after: 400 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: '1a56db' } }, children: [] }));

    // Label + Date
    children.push(new Paragraph({ spacing: { after: 80 },
      children: [new TextRun({ text: 'NOTA DE PRENSA', font: 'Arial', size: 18, bold: true, color: '999999', allCaps: true })] }));
    children.push(new Paragraph({ spacing: { after: 400 },
      children: [new TextRun({ text: `Valencia, ${fecha}`, font: 'Arial', size: 20, color: '999999' })] }));

    // ── TITULAR ──
    children.push(new Paragraph({ spacing: { after: 200, line: 300 },
      children: [new TextRun({ text: nota.titular || 'Sin titular', font: 'Georgia', size: 40, bold: true, color: '111111' })] }));

    // ── SUBTITULO ──
    if (nota.subtitulo) {
      children.push(new Paragraph({ spacing: { after: 400, line: 300 },
        children: [new TextRun({ text: nota.subtitulo, font: 'Georgia', size: 26, color: '444444' })] }));
    }

    // Thin separator
    children.push(new Paragraph({ spacing: { after: 300 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 1, color: 'DDDDDD' } }, children: [] }));

    // ── CUERPO ──
    for (const para of bodyParagraphs) {
      children.push(new Paragraph({ spacing: { after: 240, line: 360 },
        children: [new TextRun({ text: para.trim(), font: 'Arial', size: 22, color: '222222' })] }));
    }

    // ── PIE: CONTACTO ──
    children.push(new Paragraph({ spacing: { before: 500 },
      border: { top: { style: BorderStyle.SINGLE, size: 6, color: '1a56db' } }, children: [] }));
    children.push(new Paragraph({ spacing: { before: 200, after: 80 },
      children: [new TextRun({ text: 'Para m\u00e1s informaci\u00f3n:', font: 'Arial', size: 18, bold: true, color: '1a56db' })] }));
    children.push(new Paragraph({ spacing: { after: 40, line: 300 },
      children: [new TextRun({ text: nota.contactoPrensa || 'Departamento de Comunicaci\u00f3n Encom \u2014 prensa@encom.es \u2014 960 000 000', font: 'Arial', size: 20, color: '333333' })] }));
    if (nota.materialesAdjuntos) {
      children.push(new Paragraph({ spacing: { after: 40 },
        children: [new TextRun({ text: 'Materiales de prensa: ', font: 'Arial', size: 18, bold: true, color: '666666' }),
          new TextRun({ text: nota.materialesAdjuntos, font: 'Arial', size: 18, color: '1a56db' })] }));
    }

    const doc = new Document({
      styles: { default: { document: { run: { font: 'Arial', size: 22 } } } },
      sections: [{
        properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1800, right: 1600, bottom: 1440, left: 1600 } } },
        children
      }]
    });

    const buffer = await Packer.toBuffer(doc);
    const filename = `NP_${(nota.proyecto || 'Encom').replace(/\s+/g, '_')}_${fecha.replace(/\s+/g, '_')}.docx`;
    cors(res);
    res.writeHead(200, {
      'Content-Type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': buffer.length
    });
    res.end(buffer);
  } catch (e) {
    error(res, 'Error generando docx: ' + e.message, 500);
  }
});

// ── EXPORTAR NOTA COMO PDF (HTML para imprimir) ──
route('GET', '/api/notas/:id/exportar-pdf', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const notas = readJSON('notas.json');
  const nota = notas.find(n => n.id === params.id);
  if (!nota) return error(res, 'Nota no encontrada', 404);

  const fecha = new Date(nota.updatedAt || nota.createdAt).toLocaleDateString('es-ES', { day: 'numeric', month: 'long', year: 'numeric' });
  const bodyHtml = (nota.cuerpo || '').split(/\n\n+/).filter(p => p.trim()).map(p => `<p>${p.replace(/\n/g, '<br>')}</p>`).join('');

  const html = `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>Nota de prensa - ${(nota.titular || 'Encom').replace(/"/g, '')}</title>
<style>
@page { size: A4; margin: 2.5cm 2cm; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: Arial, Helvetica, sans-serif; color: #222; line-height: 1.6; max-width: 700px; margin: 0 auto; padding: 40px 20px; }
.header { text-align: right; margin-bottom: 8px; }
.header .brand { font-size: 18px; font-weight: 700; color: #1a56db; }
.header .project { font-size: 12px; color: #666; }
.blue-line { border: none; border-top: 3px solid #1a56db; margin: 16px 0 24px 0; }
.meta { font-size: 10px; color: #999; text-transform: uppercase; font-weight: 700; letter-spacing: 1px; }
.date { font-size: 11px; color: #999; margin-bottom: 24px; }
h1 { font-family: Georgia, 'Times New Roman', serif; font-size: 26px; color: #111; line-height: 1.25; margin-bottom: 10px; font-weight: 700; }
.subtitle { font-family: Georgia, serif; font-size: 15px; color: #444; line-height: 1.4; margin-bottom: 20px; }
.thin-line { border: none; border-top: 1px solid #ddd; margin: 16px 0; }
.body p { font-size: 12px; color: #222; line-height: 1.7; margin-bottom: 14px; text-align: justify; }
.footer { margin-top: 32px; border-top: 3px solid #1a56db; padding-top: 16px; }
.footer-label { font-size: 10px; font-weight: 700; color: #1a56db; margin-bottom: 4px; }
.footer-text { font-size: 11px; color: #333; line-height: 1.5; }
.footer-materials { font-size: 10px; color: #666; margin-top: 8px; }
.footer-materials a { color: #1a56db; }
@media print { body { padding: 0; max-width: none; } .no-print { display: none; } }
</style></head><body>
<div class="no-print" style="background:#1a56db;color:white;padding:12px 20px;margin:-40px -20px 30px;text-align:center;font-size:14px;border-radius:0 0 8px 8px">
  Para guardar como PDF: <strong>Ctrl+P</strong> (o Cmd+P) &rarr; Destino: <strong>Guardar como PDF</strong></div>
<div class="header"><div class="brand">ENCOM</div>${nota.proyecto ? `<div class="project">${nota.proyecto}</div>` : ''}</div>
<hr class="blue-line">
<div class="meta">NOTA DE PRENSA</div>
<div class="date">Valencia, ${fecha}</div>
<h1>${nota.titular || 'Sin titular'}</h1>
${nota.subtitulo ? `<div class="subtitle">${nota.subtitulo}</div>` : ''}
<hr class="thin-line">
<div class="body">${bodyHtml}</div>
<div class="footer">
  <div class="footer-label">Para m\u00e1s informaci\u00f3n:</div>
  <div class="footer-text">${nota.contactoPrensa || 'Departamento de Comunicaci\u00f3n Encom \u2014 prensa@encom.es \u2014 960 000 000'}</div>
  ${nota.materialesAdjuntos ? `<div class="footer-materials">Materiales: <a href="${nota.materialesAdjuntos}">${nota.materialesAdjuntos}</a></div>` : ''}
</div>
<script>window.onload = function() { setTimeout(function() { window.print(); }, 500); }</script>
</body></html>`;

  cors(res);
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
});

// ── NOTIFICATIONS ──
route('GET', '/api/notificaciones', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const notifs = readJSON('notifications.json');
  json(res, notifs.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
});

route('PATCH', '/api/notificaciones/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const notifs = readJSON('notifications.json');
  const idx = notifs.findIndex(n => n.id === params.id);
  if (idx !== -1) { notifs[idx].read = true; writeJSON('notifications.json', notifs); }
  json(res, { ok: true });
});

// ── DASHBOARD / REPORTING ──
route('GET', '/api/dashboard', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const notas = readJSON('notas.json');
  const medios = readJSON('medios.json');
  const totalNotas = notas.length;
  const estados = {};
  notas.forEach(n => { estados[n.estado] = (estados[n.estado] || 0) + 1; });
  const totalPublicaciones = notas.reduce((acc, n) => acc + (n.publicaciones || []).length, 0);
  const totalEnvios = notas.reduce((acc, n) => acc + (n.envios || []).length, 0);
  const totalMedios = medios.length;
  // By project
  const porProyecto = {};
  notas.forEach(n => {
    if (!porProyecto[n.proyecto]) porProyecto[n.proyecto] = { total: 0, publicaciones: 0, envios: 0 };
    porProyecto[n.proyecto].total++;
    porProyecto[n.proyecto].publicaciones += (n.publicaciones || []).length;
    porProyecto[n.proyecto].envios += (n.envios || []).length;
  });
  // Top medios
  const medioPubs = {};
  notas.forEach(n => {
    (n.publicaciones || []).forEach(p => {
      medioPubs[p.medio] = (medioPubs[p.medio] || 0) + 1;
    });
  });
  const topMedios = Object.entries(medioPubs).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([medio, count]) => ({ medio, publicaciones: count }));
  // Evolution (last 6 months)
  const meses = [];
  const ahora = new Date();
  for (let i = 5; i >= 0; i--) {
    const d = new Date(ahora.getFullYear(), ahora.getMonth() - i, 1);
    const label = d.toLocaleDateString('es-ES', { month: 'short', year: 'numeric' });
    const notasM = notas.filter(n => { const nd = new Date(n.createdAt); return nd.getMonth() === d.getMonth() && nd.getFullYear() === d.getFullYear(); });
    meses.push({ mes: label, notas: notasM.length, publicaciones: notasM.reduce((a, n) => a + (n.publicaciones || []).length, 0) });
  }
  // Suggestions
  const sugerencias = [];
  if (totalEnvios > 0 && totalPublicaciones / totalEnvios < 0.3) sugerencias.push('La tasa de publicación es baja. Considera personalizar más los envíos o segmentar mejor los contactos.');
  if (estados.borrador > estados.enviada) sugerencias.push('Hay más borradores que notas enviadas. Revisa el flujo de aprobación para agilizarlo.');
  const inactiveMediaCount = medios.filter(m => !m.historialEnvios || m.historialEnvios.length === 0).length;
  if (inactiveMediaCount > medios.length * 0.5) sugerencias.push(`Tienes ${inactiveMediaCount} contactos sin envíos. Considera depurar la BBDD de medios.`);
  json(res, { totalNotas, estados, totalPublicaciones, totalEnvios, totalMedios, porProyecto, topMedios, evolucion: meses, sugerencias });
});

// Reporte semanal
route('GET', '/api/reporte-semanal', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const notas = readJSON('notas.json');
  const hoy = new Date();
  const hace7 = new Date(hoy.getTime() - 7 * 24 * 60 * 60 * 1000);
  const notasSemana = notas.filter(n => new Date(n.updatedAt) >= hace7);
  const enviadas = notasSemana.filter(n => n.envios && n.envios.some(e => new Date(e.fecha) >= hace7));
  const publicadas = notasSemana.filter(n => n.publicaciones && n.publicaciones.some(p => new Date(p.fecha) >= hace7));
  const nuevasPubs = [];
  notasSemana.forEach(n => {
    (n.publicaciones || []).forEach(p => {
      if (new Date(p.fecha) >= hace7) nuevasPubs.push({ nota: n.titular, medio: p.medio, url: p.url });
    });
  });
  json(res, {
    periodo: { desde: hace7.toISOString(), hasta: hoy.toISOString() },
    notasActualizadas: notasSemana.length,
    notasEnviadas: enviadas.length,
    publicacionesConseguidas: nuevasPubs.length,
    detalle: nuevasPubs,
    sugerencias: [
      'Los envíos entre martes y jueves tienen mayor tasa de apertura.',
      'Los asuntos con datos numéricos generan más interés.',
      'Incluir citas directas mejora la tasa de publicación.'
    ]
  });
});

// ── GOOGLE NEWS SEARCH (simulation) ──
route('POST', '/api/buscar-publicaciones', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const keywords = body.keywords || '';
  // Build Google News search URL for the user
  const searchUrl = `https://news.google.com/search?q=${encodeURIComponent(keywords)}&hl=es&gl=ES`;
  json(res, { searchUrl, message: 'Usa este enlace para buscar publicaciones en Google News. Los resultados deben registrarse manualmente.' });
});

// ─── HTTP Server ──────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
    cors(res);

    // Handle preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const urlPath = parsedUrl.pathname;

    // ── SSO from Encom Tools Portal ──
    if (urlPath === '/sso' && req.method === 'GET') {
      const ssoToken = parsedUrl.searchParams.get('token');
      if (!ssoToken) { res.writeHead(302, { Location: '/' }); return res.end(); }
      try {
        console.log('[SSO] Validating token against portal:', PORTAL_URL);
        const ssoResult = await ssoValidate(ssoToken);
        console.log('[SSO] Validation result:', JSON.stringify(ssoResult));
        if (!ssoResult.valid) { res.writeHead(302, { Location: '/' }); return res.end(); }

        // Find or create user
        const users = readJSON('users.json');
        let user = users.find(u => u.email === ssoResult.user.email);
        if (!user) {
          user = { id: uuid(), email: ssoResult.user.email, name: ssoResult.user.name, password: hashPassword(crypto.randomBytes(32).toString('hex')), role: 'admin', createdAt: now() };
          users.push(user);
          writeJSON('users.json', users);
        }

        // Create session
        const sessions = readJSON('sessions.json');
        const sessionToken = generateToken();
        sessions.push({ token: sessionToken, userId: user.id, createdAt: now() });
        writeJSON('sessions.json', sessions);

        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(`<!DOCTYPE html><html><head><script>
          localStorage.setItem('token', '${sessionToken}');
          localStorage.setItem('user', JSON.stringify(${JSON.stringify({ id: user.id, email: user.email, name: user.name, role: user.role })}));
          window.location.href = '/';
        </script></head><body></body></html>`);
      } catch (err) {
        console.error('SSO validation error:', err);
        res.writeHead(302, { Location: '/' });
        return res.end();
      }
    }

    // API Routes
    for (const r of routes) {
      const params = matchRoute(req.method, urlPath, r.method, r.pattern);
      if (params !== null) {
        await r.handler(req, res, params);
        return;
      }
    }

    // External validation page (serves index.html, the SPA handles routing)
    if (urlPath.startsWith('/validar/')) {
      const fp = path.join(PUBLIC_DIR, 'index.html');
      if (fs.existsSync(fp)) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(fs.readFileSync(fp));
      }
    }

    // Static files
    let filePath = path.join(PUBLIC_DIR, urlPath === '/' ? 'index.html' : urlPath);
    filePath = path.normalize(filePath);
    if (!filePath.startsWith(PUBLIC_DIR)) return error(res, 'Forbidden', 403);

    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath);
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      return res.end(fs.readFileSync(filePath));
    }

    // Fallback to SPA
    const indexPath = path.join(PUBLIC_DIR, 'index.html');
    if (fs.existsSync(indexPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(indexPath));
    }

    error(res, 'Not found', 404);
  } catch (err) {
    console.error('Server error:', err);
    try { error(res, 'Error interno del servidor', 500); } catch {}
  }
});

server.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════╗`);
  console.log(`  ║  EncomPR — Sistema de Notas de Prensa    ║`);
  console.log(`  ║  Servidor activo en http://localhost:${PORT} ║`);
  console.log(`  ╚══════════════════════════════════════════╝\n`);
});
                                                                                                                                                                                                                                                                                                                                                                                                  