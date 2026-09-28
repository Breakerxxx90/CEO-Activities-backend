const { db, pool, hashPassword } = require('./db');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
  name TEXT NOT NULL,
  cls TEXT NOT NULL DEFAULT 'Student',
  uni TEXT NOT NULL DEFAULT '',
  avatar TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE UNIQUE INDEX IF NOT EXISTS users_username_key ON users(lower(username));
CREATE TABLE IF NOT EXISTS categories(
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE UNIQUE INDEX IF NOT EXISTS categories_name_key ON categories(lower(name));
CREATE TABLE IF NOT EXISTS activities(
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE RESTRICT,
  hours INTEGER NOT NULL DEFAULT 0,
  description TEXT NOT NULL DEFAULT '',
  image TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS views(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  activity_id INTEGER NOT NULL REFERENCES activities(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, activity_id));
CREATE TABLE IF NOT EXISTS joins(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  activity_id INTEGER NOT NULL REFERENCES activities(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(user_id, activity_id));
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS uploads(
  name TEXT PRIMARY KEY,
  mime TEXT NOT NULL,
  data BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
`;

async function migrate() {
  await db.exec(SCHEMA);
  if (!(await db.get('SELECT 1 AS x FROM categories'))) {
    for (const n of ['exercise', 'Skills', 'Fun and learning'])
      await db.run('INSERT INTO categories(name) VALUES(?) ON CONFLICT DO NOTHING', n);
  }
  if (!(await db.get("SELECT 1 AS x FROM users WHERE role='admin'"))) {
    const u = process.env.ADMIN_USER || 'admin';
    const fromEnv = !!process.env.ADMIN_PASSWORD;
    const p = process.env.ADMIN_PASSWORD || 'admin1234';
    await db.run("INSERT INTO users(username,password_hash,role,name,cls) VALUES(?,?,'admin',?,'Admin')",
      u, await hashPassword(p), u);
    console.log(`\n[setup] สร้างบัญชีแอดมินแล้ว  username: ${u}  password: ${fromEnv ? '(ตาม ADMIN_PASSWORD ที่ตั้งไว้)' : p}\n`);
    if (!fromEnv) console.warn('[setup] คำเตือน: ใช้รหัสผ่านเริ่มต้น ควรตั้ง ADMIN_PASSWORD หรือรัน reset-admin.js ทันที');
  }
}

module.exports = migrate;
if (require.main === module)
  migrate().then(() => console.log('migrate เสร็จแล้ว')).catch(e => { console.error(e); process.exitCode = 1; }).finally(() => pool.end());