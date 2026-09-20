require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

function cycleForDate(dateString) {
  const d = new Date(dateString + "T00:00:00");
  let y = d.getFullYear();
  let m = d.getMonth();

  // Cycle folder is named by its ending month:
  // JAN 2026 = 26-Dec-2025 -> 25-Jan-2026
  if (d.getDate() >= 26) {
    m += 1;
    if (m === 12) { m = 0; y += 1; }
  }

  const pad = n => String(n).padStart(2, "0");
  return `${y}-${pad(m + 1)}`;
}

function minutesBetween(from, to) {
  const [fh, fm] = from.split(":").map(Number);
  const [th, tm] = to.split(":").map(Number);
  let a = fh * 60 + fm;
  let b = th * 60 + tm;
  if (b <= a) b += 1440;
  return (b - a) / 60;
}

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "30d" });
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Login required" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Session expired. Login again." });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch {
    res.status(503).json({ ok: false, database: "not connected" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { role, loginId, password } = req.body;
  if (!role || !loginId || !password)
    return res.status(400).json({ error: "Login details required" });

  if (role === "admin") {
    const r = await pool.query("SELECT * FROM admins WHERE login_id=$1", [loginId]);
    if (!r.rowCount || !(await bcrypt.compare(password, r.rows[0].password_hash)))
      return res.status(401).json({ error: "Invalid login" });
    return res.json({
      token: signToken({ role: "admin", adminId: r.rows[0].id }),
      user: { role: "admin", loginId }
    });
  }

  const r = await pool.query(
    "SELECT * FROM employees WHERE employee_name ILIKE $1 AND active=true",
    [loginId]
  );
  if (!r.rowCount || !(await bcrypt.compare(password, r.rows[0].password_hash)))
    return res.status(401).json({ error: "Invalid login" });

  const e = r.rows[0];
  res.json({
    token: signToken({ role: "employee", employeeId: e.id }),
    user: { role: "employee", id: e.id, employeeCode: e.employee_code, name: e.employee_name }
  });
});

app.post("/api/auth/change-admin-password", auth, adminOnly, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6)
    return res.status(400).json({ error: "New password must be at least 6 characters" });

  const r = await pool.query("SELECT * FROM admins WHERE id=$1", [req.user.adminId]);
  if (!r.rowCount || !(await bcrypt.compare(currentPassword, r.rows[0].password_hash)))
    return res.status(401).json({ error: "Current password is incorrect" });

  const hash = await bcrypt.hash(newPassword, 12);
  await pool.query("UPDATE admins SET password_hash=$1 WHERE id=$2", [hash, req.user.adminId]);
  res.json({ ok: true });
});

app.get("/api/me", auth, async (req, res) => {
  if (req.user.role === "admin") return res.json({ role: "admin" });
  const r = await pool.query(
    "SELECT id, employee_code, employee_name, active FROM employees WHERE id=$1",
    [req.user.employeeId]
  );
  if (!r.rowCount || !r.rows[0].active) return res.status(403).json({ error: "Employee disabled" });
  res.json({ role: "employee", ...r.rows[0] });
});

app.get("/api/settings/rate", auth, async (_req, res) => {
  const r = await pool.query("SELECT standard_rate FROM ot_settings WHERE id=1");
  res.json({ rate: Number(r.rows[0].standard_rate) });
});

app.put("/api/settings/rate", auth, adminOnly, async (req, res) => {
  const rate = Number(req.body.rate);
  if (!Number.isFinite(rate) || rate < 0)
    return res.status(400).json({ error: "Invalid rate" });
  await pool.query(
    "UPDATE ot_settings SET standard_rate=$1, updated_at=NOW() WHERE id=1",
    [rate]
  );
  res.json({ ok: true, rate });
});

app.post("/api/employees", auth, adminOnly, async (req, res) => {
  const { employeeCode, employeeName } = req.body;
  if (!employeeCode || !employeeName)
    return res.status(400).json({ error: "Employee ID and name required" });

  const passwordHash = await bcrypt.hash(employeeCode, 12);
  try {
    const r = await pool.query(
      `INSERT INTO employees(employee_code, employee_name, password_hash)
       VALUES($1,$2,$3)
       RETURNING id, employee_code, employee_name, active`,
      [employeeCode.toUpperCase(), employeeName, passwordHash]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Employee already exists" });
    throw e;
  }
});

app.get("/api/employees", auth, adminOnly, async (_req, res) => {
  const r = await pool.query(
    "SELECT id, employee_code, employee_name, active, created_at FROM employees ORDER BY employee_name"
  );
  res.json(r.rows);
});

app.patch("/api/employees/:id/status", auth, adminOnly, async (req, res) => {
  const active = Boolean(req.body.active);
  await pool.query("UPDATE employees SET active=$1 WHERE id=$2", [active, req.params.id]);
  res.json({ ok: true });
});

app.delete("/api/employees/:id", auth, adminOnly, async (req, res) => {
  // Keep OT history while removing the login account.
  await pool.query("DELETE FROM employees WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

app.post("/api/ot", auth, async (req, res) => {
  if (req.user.role !== "employee")
    return res.status(403).json({ error: "Employee only" });

  const { date, from, to, sundayMultiplier = 1 } = req.body;
  if (!date || !from || !to)
    return res.status(400).json({ error: "Date and OT times required" });

  const day = new Date(date + "T00:00:00").getDay();
  const multiplier = day === 0 ? Number(sundayMultiplier) : 1;
  if (![1, 2].includes(multiplier))
    return res.status(400).json({ error: "Invalid Sunday multiplier" });

  const hours = minutesBetween(from, to) / 60;
  if (hours <= 0) return res.status(400).json({ error: "Invalid OT time" });

  const rateRow = await pool.query("SELECT standard_rate FROM ot_settings WHERE id=1");
  const rate = Number(rateRow.rows[0].standard_rate);
  const amount = hours * rate * multiplier;
  const cycleKey = cycleForDate(date);

  try {
    const r = await pool.query(
      `INSERT INTO ot_entries(employee_id,ot_date,ot_from,ot_to,hours,multiplier,rate,amount,cycle_key)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING *`,
      [req.user.employeeId, date, from, to, hours, multiplier, rate, amount, cycleKey]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    if (e.code === "23505")
      return res.status(409).json({ error: "This employee already has an OT entry for this date." });
    throw e;
  }
});

app.get("/api/ot/my", auth, async (req, res) => {
  if (req.user.role !== "employee")
    return res.status(403).json({ error: "Employee only" });

  const r = await pool.query(
    `SELECT * FROM ot_entries
     WHERE employee_id=$1
     ORDER BY ot_date DESC, id DESC`,
    [req.user.employeeId]
  );
  res.json(r.rows);
});

app.delete("/api/ot/:id", auth, async (req, res) => {
  if (req.user.role !== "employee")
    return res.status(403).json({ error: "Employee only" });

  await pool.query(
    "DELETE FROM ot_entries WHERE id=$1 AND employee_id=$2",
    [req.params.id, req.user.employeeId]
  );
  res.json({ ok: true });
});

app.get("/api/ot/all", auth, adminOnly, async (_req, res) => {
  const r = await pool.query(
    `SELECT o.*, e.employee_code, e.employee_name
     FROM ot_entries o
     JOIN employees e ON e.id=o.employee_id
     ORDER BY o.ot_date DESC, o.id DESC`
  );
  res.json(r.rows);
});

async function bootstrap() {
  // Schema must be applied before starting in production.
  if (process.env.RUN_SCHEMA === "true") {
    const sql = fs.readFileSync(__dirname + "/schema.sql", "utf8");
    await pool.query(sql);
  }

  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => console.log(`OT server running on port ${port}`));
}

bootstrap().catch(err => {
  console.error(err);
  process.exit(1);
});
