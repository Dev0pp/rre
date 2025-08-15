
const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = process.env.PORT || 3000;

// إعداد التخزين
const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// SQLite database setup
const db = new sqlite3.Database('database.db');
db.run("CREATE TABLE IF NOT EXISTS users (id TEXT, serial TEXT, file TEXT)");

// Middleware
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Redirect root to login.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// API: رفع ملف PDF وتسجيل البيانات
app.post('/upload', upload.single('file'), (req, res) => {
  console.log("استلام البيانات:", req.body);
  console.log("استلام الملف:", req.file);
  const { id, serial } = req.body;
  if (!req.file) return res.status(400).json({ success: false, message: "No file uploaded" });
  const file = req.file.filename;
  db.run("INSERT INTO users (id, serial, file) VALUES (?, ?, ?)", [id, serial, file], (err) => {
    if (err) {
      console.error("خطأ في حفظ البيانات:", err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    console.log("تم حفظ المستخدم:", id, serial, file);
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true });
  });
});

// API: جلب المستخدمين
app.get('/users', (req, res) => {
  db.all("SELECT * FROM users", [], (err, rows) => {
    if (err) return res.status(500).json({ success: false });
    res.json(rows);
  });
});

app.listen(PORT, () => console.log("Server running at http://localhost:" + PORT));


app.post('/delete-user', (req, res) => {
  const { id, serial } = req.body;
  db.run("DELETE FROM users WHERE id = ? AND serial = ?", [id, serial], function(err) {
    if (err) {
      console.error(err.message);
      res.status(500).send("خطأ في حذف المستخدم");
    } else {
      res.sendStatus(200);
    }
  });
});
