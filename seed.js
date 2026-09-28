// เพิ่มกิจกรรมตัวอย่าง
const { db, pool } = require('./db');
const migrate = require('./migrate');

const SAMPLE = [
  ['วิ่งเช้า', 'exercise', 2, 'วิ่งออกกำลังกายยามเช้า'],
  ['โยคะ', 'exercise', 0, 'โยคะผ่อนคลายสำหรับมือใหม่'],
  ['ถ่ายภาพเบื้องต้น', 'Skills', 3, 'เรียนรู้พื้นฐานการถ่ายภาพ'],
  ['เกมทายคำ', 'Fun and learning', 1, 'เกมทายคำสนุกๆ กับเพื่อน'],
];

migrate().then(async () => {
  if (await db.get('SELECT 1 AS x FROM activities')) return console.log('มีกิจกรรมอยู่แล้ว ข้ามการ seed');
  for (const [name, c, hours, desc] of SAMPLE) {
    const r = await db.get('SELECT id FROM categories WHERE lower(name)=lower(?)', c);
    if (r) await db.run('INSERT INTO activities(name,category_id,hours,description) VALUES(?,?,?,?)', name, r.id, hours, desc);
  }
  console.log('เพิ่มกิจกรรมตัวอย่างแล้ว');
}).catch(e => { console.error(e); process.exitCode = 1; }).finally(() => pool.end());