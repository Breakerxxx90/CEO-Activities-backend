
const { db, pool, hashPassword } = require('./db');
const pw = process.argv[2] || 'admin1234';
(async () => {
  const r = await db.run("UPDATE users SET password_hash=? WHERE role='admin'", await hashPassword(pw));
  console.log(r.changes ? 'ตั้งรหัสแอดมินเป็น: ' + pw : 'ไม่พบบัญชีแอดมิน (รัน npm run migrate ก่อน)');
})().catch(e => { console.error(e); process.exitCode = 1; }).finally(() => pool.end());