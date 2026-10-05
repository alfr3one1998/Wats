import { createServer } from 'node:http';
import { mkdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, 'public');
const MAX_BODY_SIZE = 1_000_000;
const SESSION_DURATION_MS = 1000 * 60 * 60 * 24 * 14;

const MIME_TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml'
};

function bool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

export function getConfig(env = process.env) {
  const production = env.NODE_ENV === 'production';
  const adminPassword = env.ADMIN_PASSWORD || (production ? '' : 'admin123');
  const cookieSecret = env.COOKIE_SECRET || (production ? '' : 'local-development-secret-change-me');

  if (production && (!adminPassword || !cookieSecret)) {
    throw new Error('في الإنتاج يجب ضبط ADMIN_PASSWORD و COOKIE_SECRET.');
  }

  return {
    port: Number(env.PORT || 3000),
    production,
    adminPassword,
    cookieSecret,
    dataPath: env.DATA_PATH || join(__dirname, 'data', 'wats.sqlite'),
    verifyToken: env.WHATSAPP_VERIFY_TOKEN || '',
    appSecret: env.WHATSAPP_APP_SECRET || '',
    secureCookies: production || bool(env.SECURE_COOKIES),
    trustProxy: bool(env.TRUST_PROXY),
    enableDemo: bool(env.ENABLE_DEMO, !production)
  };
}

export function openDatabase(path) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS contacts (
      phone TEXT PRIMARY KEY,
      whatsapp_name TEXT,
      custom_name TEXT,
      labels TEXT NOT NULL DEFAULT '[]',
      first_message_at INTEGER NOT NULL,
      last_message_at INTEGER NOT NULL,
      last_message_preview TEXT,
      last_message_type TEXT,
      total_messages INTEGER NOT NULL DEFAULT 0,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message_id TEXT UNIQUE,
      phone TEXT NOT NULL,
      message_type TEXT NOT NULL,
      body TEXT,
      timestamp INTEGER NOT NULL,
      direction TEXT NOT NULL DEFAULT 'inbound',
      created_at INTEGER NOT NULL,
      FOREIGN KEY (phone) REFERENCES contacts(phone) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_contacts_last_message ON contacts(last_message_at DESC);
    CREATE INDEX IF NOT EXISTS idx_messages_phone_timestamp ON messages(phone, timestamp DESC);
  `);
  return db;
}

function sendJson(response, status, data, headers = {}) {
  const payload = JSON.stringify(data);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
    ...headers
  });
  response.end(payload);
}

function sendText(response, status, text, headers = {}) {
  response.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'cache-control': 'no-store',
    ...headers
  });
  response.end(text);
}

function securityHeaders(response) {
  response.setHeader('x-content-type-options', 'nosniff');
  response.setHeader('x-frame-options', 'DENY');
  response.setHeader('referrer-policy', 'strict-origin-when-cross-origin');
  response.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  response.setHeader(
    'content-security-policy',
    "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'"
  );
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_SIZE) {
        reject(new Error('الطلب أكبر من الحجم المسموح.'));
        request.resume();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

function parseJson(buffer) {
  try {
    return JSON.parse(buffer.toString('utf8'));
  } catch {
    return null;
  }
}

function parseCookies(header = '') {
  return Object.fromEntries(
    header
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const separator = part.indexOf('=');
        return separator === -1
          ? [part, '']
          : [part.slice(0, separator), decodeURIComponent(part.slice(separator + 1))];
      })
  );
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function sign(value, secret) {
  return createHmac('sha256', secret).update(value).digest('base64url');
}

function makeSession(secret) {
  const payload = Buffer.from(
    JSON.stringify({ expiresAt: Date.now() + SESSION_DURATION_MS, nonce: randomBytes(16).toString('hex') })
  ).toString('base64url');
  return `${payload}.${sign(payload, secret)}`;
}

function readSession(request, secret) {
  const token = parseCookies(request.headers.cookie).session;
  if (!token || !token.includes('.')) return false;
  const [payload, signature] = token.split('.', 2);
  if (!safeEqual(signature, sign(payload, secret))) return false;
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')).expiresAt > Date.now();
  } catch {
    return false;
  }
}

function sessionCookie(value, config) {
  return [
    `session=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.floor(SESSION_DURATION_MS / 1000)}`,
    config.secureCookies ? 'Secure' : ''
  ]
    .filter(Boolean)
    .join('; ');
}

function expiredSessionCookie(config) {
  return [
    'session=',
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
    config.secureCookies ? 'Secure' : ''
  ]
    .filter(Boolean)
    .join('; ');
}

function normalizePhone(value) {
  const phone = String(value || '').replace(/\D/g, '');
  return phone.length >= 7 && phone.length <= 20 ? phone : '';
}

function cleanText(value, max = 500) {
  return String(value || '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

function normaliseLabels(value) {
  const values = Array.isArray(value) ? value : String(value || '').split(/[,،]/);
  return [...new Set(values.map((item) => cleanText(item, 24)).filter(Boolean))].slice(0, 8);
}

function labelsFromDatabase(value) {
  try {
    const labels = JSON.parse(value || '[]');
    return Array.isArray(labels) ? labels : [];
  } catch {
    return [];
  }
}

function serializeContact(contact) {
  if (!contact) return null;
  const customName = cleanText(contact.custom_name, 80);
  const whatsappName = cleanText(contact.whatsapp_name, 80);
  return {
    ...contact,
    custom_name: customName || null,
    whatsapp_name: whatsappName || null,
    labels: labelsFromDatabase(contact.labels),
    display_name: customName || whatsappName || 'بدون اسم'
  };
}

function descriptionForMessage(message) {
  const caption = cleanText(message?.[message?.type]?.caption, 180);
  switch (message?.type) {
    case 'text':
      return cleanText(message.text?.body, 500) || 'رسالة نصية';
    case 'image':
      return caption ? `صورة: ${caption}` : 'صورة';
    case 'video':
      return caption ? `فيديو: ${caption}` : 'فيديو';
    case 'audio':
      return 'رسالة صوتية';
    case 'document':
      return message.document?.filename ? `ملف: ${cleanText(message.document.filename, 120)}` : 'ملف';
    case 'sticker':
      return 'ملصق';
    case 'location':
      return 'موقع';
    case 'contacts':
      return 'جهة اتصال';
    case 'interactive':
      return cleanText(message.interactive?.button_reply?.title || message.interactive?.list_reply?.title, 180) || 'تفاعل';
    case 'button':
      return cleanText(message.button?.text, 180) || 'زر';
    default:
      return cleanText(message?.type, 80) || 'رسالة جديدة';
  }
}

export function webhookMessages(payload) {
  const result = [];
  for (const entry of payload?.entry || []) {
    for (const change of entry?.changes || []) {
      const value = change?.value || {};
      const profiles = new Map(
        (value.contacts || []).map((contact) => [
          String(contact.wa_id || ''),
          cleanText(contact.profile?.name, 80)
        ])
      );
      for (const message of value.messages || []) {
        const phone = normalizePhone(message.from);
        if (!phone) continue;
        const timestamp = Number(message.timestamp) * 1000;
        result.push({
          phone,
          messageId: cleanText(message.id, 160) || null,
          whatsappName: profiles.get(String(message.from)) || '',
          messageType: cleanText(message.type, 40) || 'unknown',
          body: descriptionForMessage(message),
          timestamp: Number.isFinite(timestamp) && timestamp > 0 ? timestamp : Date.now()
        });
      }
    }
  }
  return result;
}

export function saveInboundMessage(db, incoming) {
  const now = Date.now();
  const messageId = incoming.messageId || `local-${incoming.phone}-${incoming.timestamp}-${createHmac('sha256', 'fallback').update(incoming.body).digest('hex').slice(0, 12)}`;
  const existingContact = db.prepare('SELECT phone FROM contacts WHERE phone = ?').get(incoming.phone);

  if (!existingContact) {
    db.prepare(`
      INSERT INTO contacts (phone, whatsapp_name, custom_name, labels, first_message_at, last_message_at, last_message_preview, last_message_type, total_messages, updated_at)
      VALUES (?, ?, NULL, '[]', ?, ?, ?, ?, 0, ?)
    `).run(
      incoming.phone,
      incoming.whatsappName || null,
      incoming.timestamp,
      incoming.timestamp,
      incoming.body,
      incoming.messageType,
      now
    );
  }

  const messageResult = db.prepare(`
    INSERT OR IGNORE INTO messages (message_id, phone, message_type, body, timestamp, direction, created_at)
    VALUES (?, ?, ?, ?, ?, 'inbound', ?)
  `).run(messageId, incoming.phone, incoming.messageType, incoming.body, incoming.timestamp, now);

  if (messageResult.changes === 0) return false;

  db.prepare(`
    UPDATE contacts
    SET whatsapp_name = CASE WHEN ? != '' THEN ? ELSE whatsapp_name END,
        last_message_at = ?,
        last_message_preview = ?,
        last_message_type = ?,
        total_messages = total_messages + 1,
        updated_at = ?
    WHERE phone = ?
  `).run(
    incoming.whatsappName,
    incoming.whatsappName,
    incoming.timestamp,
    incoming.body,
    incoming.messageType,
    now,
    incoming.phone
  );
  return true;
}

function startOfRiyadhDay() {
  const now = new Date();
  const riyadh = new Date(now.getTime() + 3 * 60 * 60 * 1000);
  return Date.UTC(riyadh.getUTCFullYear(), riyadh.getUTCMonth(), riyadh.getUTCDate()) - 3 * 60 * 60 * 1000;
}

export function getStats(db) {
  const dayStart = startOfRiyadhDay();
  const totals = db.prepare(`
    SELECT
      COUNT(*) AS contacts,
      COALESCE(SUM(total_messages), 0) AS messages,
      COALESCE(SUM(CASE WHEN first_message_at >= ? THEN 1 ELSE 0 END), 0) AS new_today,
      COALESCE(SUM(CASE WHEN custom_name IS NOT NULL AND TRIM(custom_name) != '' THEN 1 ELSE 0 END), 0) AS named
    FROM contacts
  `).get(dayStart);
  return totals;
}

export function getContacts(db, { query = '', filter = 'all', limit = 300 } = {}) {
  const clauses = [];
  const parameters = [];
  const cleanQuery = cleanText(query, 80);
  if (cleanQuery) {
    const like = `%${cleanQuery.replace(/[\\%_]/g, '\\$&')}%`;
    clauses.push("(phone LIKE ? ESCAPE '\\' OR COALESCE(custom_name, '') LIKE ? ESCAPE '\\' OR COALESCE(whatsapp_name, '') LIKE ? ESCAPE '\\')");
    parameters.push(like, like, like);
  }
  if (filter === 'named') clauses.push("custom_name IS NOT NULL AND TRIM(custom_name) != ''");
  if (filter === 'unnamed') clauses.push("custom_name IS NULL OR TRIM(custom_name) = ''");
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  parameters.push(Math.min(Math.max(Number(limit) || 300, 1), 500));
  return db
    .prepare(`SELECT * FROM contacts ${where} ORDER BY last_message_at DESC LIMIT ?`)
    .all(...parameters)
    .map(serializeContact);
}

export function getContact(db, phone) {
  return serializeContact(db.prepare('SELECT * FROM contacts WHERE phone = ?').get(phone));
}

function getMessages(db, phone) {
  return db
    .prepare('SELECT message_id, message_type, body, timestamp, direction FROM messages WHERE phone = ? ORDER BY timestamp DESC LIMIT 100')
    .all(phone);
}

function csvCell(value) {
  const text = String(value ?? '');
  const protectedText = /^[=+\-@]/.test(text) ? `'${text}` : text;
  return `"${protectedText.replaceAll('"', '""')}"`;
}

export function createCsv(contacts) {
  const lines = [
    ['الاسم', 'رقم واتساب', 'اسم واتساب الظاهر', 'الوسوم', 'أول رسالة', 'آخر رسالة', 'إجمالي الرسائل']
      .map(csvCell)
      .join(',')
  ];
  for (const contact of contacts) {
    lines.push(
      [
        contact.display_name,
        `+${contact.phone}`,
        contact.whatsapp_name || '',
        contact.labels.join('، '),
        new Date(contact.first_message_at).toISOString(),
        new Date(contact.last_message_at).toISOString(),
        contact.total_messages
      ]
        .map(csvCell)
        .join(',')
    );
  }
  return `\uFEFF${lines.join('\r\n')}`;
}

function originFromRequest(request, config) {
  const protocol = config.trustProxy
    ? String(request.headers['x-forwarded-proto'] || 'https').split(',')[0].trim()
    : config.secureCookies
      ? 'https'
      : 'http';
  return `${protocol}://${request.headers.host || `localhost:${config.port}`}`;
}

export function signatureIsValid(rawBody, providedSignature, appSecret) {
  if (!appSecret) return false;
  const expected = `sha256=${createHmac('sha256', appSecret).update(rawBody).digest('hex')}`;
  return safeEqual(providedSignature || '', expected);
}

function createLoginRateLimiter() {
  const attempts = new Map();
  return (key) => {
    const now = Date.now();
    const current = attempts.get(key) || { count: 0, startedAt: now };
    if (now - current.startedAt > 15 * 60 * 1000) {
      attempts.set(key, { count: 1, startedAt: now });
      return true;
    }
    if (current.count >= 8) return false;
    current.count += 1;
    attempts.set(key, current);
    return true;
  };
}

async function serveStatic(response, path) {
  const files = {
    '/': 'index.html',
    '/index.html': 'index.html',
    '/app.js': 'app.js',
    '/styles.css': 'styles.css'
  };
  const filename = files[path];
  if (!filename) return false;
  const content = await readFile(join(PUBLIC_DIR, filename));
  const extension = filename.slice(filename.lastIndexOf('.'));
  response.writeHead(200, {
    'content-type': MIME_TYPES[extension] || 'application/octet-stream',
    'cache-control': 'public, max-age=3600'
  });
  response.end(content);
  return true;
}

export function createApp({ env = process.env } = {}) {
  const config = getConfig(env);
  const db = openDatabase(config.dataPath);
  const loginAllowed = createLoginRateLimiter();

  const server = createServer(async (request, response) => {
    securityHeaders(response);
    const url = new URL(request.url || '/', originFromRequest(request, config));
    const path = url.pathname;

    try {
      if (request.method === 'GET' && path === '/webhook') {
        const mode = url.searchParams.get('hub.mode');
        const token = url.searchParams.get('hub.verify_token');
        const challenge = url.searchParams.get('hub.challenge');
        if (mode === 'subscribe' && challenge && config.verifyToken && safeEqual(token || '', config.verifyToken)) {
          sendText(response, 200, challenge);
        } else {
          sendJson(response, 403, { error: 'فشل التحقق من Webhook.' });
        }
        return;
      }

      if (request.method === 'POST' && path === '/webhook') {
        const rawBody = await readBody(request);
        const signature = request.headers['x-hub-signature-256'];
        const acceptsUnsigned = !config.production && !config.appSecret;
        if (!acceptsUnsigned && !signatureIsValid(rawBody, signature, config.appSecret)) {
          sendJson(response, 401, { error: 'توقيع Webhook غير صالح.' });
          return;
        }
        const payload = parseJson(rawBody);
        if (!payload) {
          sendJson(response, 400, { error: 'بيانات Webhook ليست JSON صالحًا.' });
          return;
        }
        let stored = 0;
        db.exec('BEGIN');
        try {
          for (const incoming of webhookMessages(payload)) {
            if (saveInboundMessage(db, incoming)) stored += 1;
          }
          db.exec('COMMIT');
        } catch (error) {
          db.exec('ROLLBACK');
          throw error;
        }
        sendJson(response, 200, { received: true, stored });
        return;
      }

      if (request.method === 'GET' && path === '/api/health') {
        sendJson(response, 200, {
          ok: true,
          webhook_ready: Boolean(config.verifyToken && config.appSecret),
          storage: 'sqlite'
        });
        return;
      }

      if (request.method === 'GET' && path === '/api/session') {
        sendJson(response, 200, { authenticated: readSession(request, config.cookieSecret) });
        return;
      }

      if (request.method === 'POST' && path === '/api/login') {
        const clientKey = String(request.headers['x-forwarded-for'] || request.socket.remoteAddress || 'unknown').split(',')[0].trim();
        if (!loginAllowed(clientKey)) {
          sendJson(response, 429, { error: 'محاولات كثيرة. انتظر 15 دقيقة ثم جرّب مجددًا.' });
          return;
        }
        const body = parseJson(await readBody(request));
        const password = typeof body?.password === 'string' && body.password.length <= 200 ? body.password : '';
        if (!body || !safeEqual(password, config.adminPassword)) {
          sendJson(response, 401, { error: 'كلمة المرور غير صحيحة.' });
          return;
        }
        sendJson(
          response,
          200,
          { authenticated: true },
          { 'set-cookie': sessionCookie(makeSession(config.cookieSecret), config) }
        );
        return;
      }

      if (request.method === 'POST' && path === '/api/logout') {
        sendJson(response, 200, { authenticated: false }, { 'set-cookie': expiredSessionCookie(config) });
        return;
      }

      const authenticated = readSession(request, config.cookieSecret);
      if (path.startsWith('/api/') && !authenticated) {
        sendJson(response, 401, { error: 'سجّل الدخول أولًا.' });
        return;
      }

      if (request.method === 'GET' && path === '/api/dashboard') {
        sendJson(response, 200, {
          stats: getStats(db),
          contacts: getContacts(db, {
            query: url.searchParams.get('q') || '',
            filter: url.searchParams.get('filter') || 'all'
          }),
          connection: {
            webhook_url: `${originFromRequest(request, config)}/webhook`,
            ready: Boolean(config.verifyToken && config.appSecret),
            signature_protection: Boolean(config.appSecret)
          }
        });
        return;
      }

      if (request.method === 'GET' && path === '/api/contacts.csv') {
        const csv = createCsv(getContacts(db, { limit: 500 }));
        response.writeHead(200, {
          'content-type': 'text/csv; charset=utf-8',
          'content-disposition': 'attachment; filename="wats-customers.csv"',
          'cache-control': 'no-store'
        });
        response.end(csv);
        return;
      }

      if (request.method === 'POST' && path === '/api/demo/inbound') {
        if (!config.enableDemo) {
          sendJson(response, 404, { error: 'وضع التجربة غير مفعّل.' });
          return;
        }
        const body = parseJson(await readBody(request)) || {};
        const phone = normalizePhone(body.phone);
        if (!phone) {
          sendJson(response, 400, { error: 'اكتب رقم واتساب صالحًا.' });
          return;
        }
        const incoming = {
          phone,
          messageId: `demo-${randomBytes(12).toString('hex')}`,
          whatsappName: cleanText(body.name, 80),
          messageType: 'text',
          body: cleanText(body.message, 500) || 'رسالة تجريبية',
          timestamp: Date.now()
        };
        saveInboundMessage(db, incoming);
        sendJson(response, 201, { contact: getContact(db, phone) });
        return;
      }

      const contactMatch = path.match(/^\/api\/contacts\/(\d+)$/);
      if (contactMatch) {
        const phone = normalizePhone(contactMatch[1]);
        if (!phone) {
          sendJson(response, 400, { error: 'رقم العميل غير صالح.' });
          return;
        }
        if (request.method === 'GET') {
          const contact = getContact(db, phone);
          if (!contact) {
            sendJson(response, 404, { error: 'العميل غير موجود.' });
            return;
          }
          sendJson(response, 200, { contact, messages: getMessages(db, phone) });
          return;
        }
        if (request.method === 'PATCH') {
          const body = parseJson(await readBody(request));
          if (!body) {
            sendJson(response, 400, { error: 'بيانات التعديل غير صالحة.' });
            return;
          }
          const contact = getContact(db, phone);
          if (!contact) {
            sendJson(response, 404, { error: 'العميل غير موجود.' });
            return;
          }
          const name = cleanText(body.custom_name, 80) || null;
          const labels = normaliseLabels(body.labels);
          db.prepare('UPDATE contacts SET custom_name = ?, labels = ?, updated_at = ? WHERE phone = ?').run(
            name,
            JSON.stringify(labels),
            Date.now(),
            phone
          );
          sendJson(response, 200, { contact: getContact(db, phone) });
          return;
        }
      }

      if (await serveStatic(response, path)) return;
      sendJson(response, 404, { error: 'الصفحة غير موجودة.' });
    } catch (error) {
      if (!response.headersSent) {
        const status = error.message === 'الطلب أكبر من الحجم المسموح.' ? 413 : 500;
        sendJson(response, status, { error: status === 413 ? error.message : 'حدث خطأ داخلي.' });
      } else {
        response.end();
      }
      console.error(error);
    }
  });

  return {
    server,
    db,
    config,
    close() {
      db.close();
    }
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const app = createApp();
  app.server.listen(app.config.port, () => {
    console.log(`Wats يعمل على http://localhost:${app.config.port}`);
    if (!app.config.production && process.env.ADMIN_PASSWORD === undefined) {
      console.log('وضع التطوير فقط: كلمة المرور الافتراضية هي admin123. غيّرها قبل النشر.');
    }
    if (!app.config.verifyToken || !app.config.appSecret) {
      console.log('Webhooks غير مربوطة بعد: اضبط WHATSAPP_VERIFY_TOKEN و WHATSAPP_APP_SECRET.');
    }
  });
  const stop = () => {
    app.server.close(() => app.close());
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
