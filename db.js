// เชื่อมฐานข้อมูล PostgreSQL (Neon)
const crypto = require('crypto');
const { promisify } = require('util');
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('ไม่พบ DATABASE_URL — ตั้งค่าเป็น connection string ของ Neon (postgresql://...?sslmode=require)');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 20000,   // เผื่อ Neon ตื่นจากโหมดหลับ
});
// Neon อาจตัดการเชื่อมต่อที่ว่างอยู่ — ดัก error ไว้ไม่ให้เซิร์ฟเวอร์ล่ม
pool.on('error', e => console.error('[pg] idle client error:', e.message));

// แปลง ? เป็น $1,$2,... เพื่อให้เขียน SQL สไตล์เดิมได้
const toPg = s => { let i = 0; return s.replace(/\?/g, () => '$' + (++i)); };
const q = (text, args = []) => pool.query(toPg(text), args);

const db = {
  all: async (text, ...args) => (await q(text, args)).rows,
  get: async (text, ...args) => (await q(text, args)).rows[0] || null,
  run: async (text, ...args) => { const r = await q(text, args); return { changes: r.rowCount, rows: r.rows }; },
  exec: text => pool.query(text),
};

const scrypt = promisify(crypto.scrypt);
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 64);
  return `scrypt:${salt.toString('hex')}:${h.toString('hex')}`;
}
async function verifyPassword(pw, stored) {
  const [alg, s, h] = String(stored).split(':');
  if (alg !== 'scrypt' || !s || !h) return false;
  const calc = await scrypt(pw, Buffer.from(s, 'hex'), 64);
  const want = Buffer.from(h, 'hex');
  return calc.length === want.length && crypto.timingSafeEqual(calc, want);
}

module.exports = { db, pool, hashPassword, verifyPassword };