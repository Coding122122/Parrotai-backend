require("dotenv").config();
const express  = require("express");
const cors     = require("cors");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const { v4: uuid } = require("uuid");
const Database = require("better-sqlite3");
const path     = require("path");
const fs       = require("fs");
const rateLimit = require("express-rate-limit");
const PORT       = process.env.PORT || 5000;
const JWT_EXP    = process.env.JWT_EXPIRES_IN || "7d";
const DB_PATH    = path.resolve(__dirname, process.env.DB_PATH || "./db/parrotai.db");
const xss = require('xss');
// ── DB bootstrap ──────────────────────────────────
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    avatar_color  TEXT DEFAULT '#2ec4b6',
    created_at    TEXT DEFAULT (datetime('now')),
    last_login    TEXT
  );
`);

// ── app ───────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || "http://localhost:3000", credentials: true }));
// ── RATE LIMITING ──────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { ok: false, message: "Too many login attempts. Try again after 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { ok: false, message: "Too many registration attempts. Try again after 1 hour." },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});
// ── helpers ───────────────────────────────────────
const COLORS = ["#2ec4b6","#38c878","#fb8500","#ffb703","#e63946","#457b9d","#a8e6a3","#f5c542"];
const pick   = a => a[Math.floor(Math.random()*a.length)];
const sign   = u => jwt.sign({ id:u.id, email:u.email, name:u.name }, JWT_SECRET, { expiresIn:JWT_EXP });
const safe   = ({ password_hash, ...r }) => r;

function authGuard(req,res,next){
  const h = req.headers.authorization;
  if(!h||!h.startsWith("Bearer ")) return res.status(401).json({ok:false,message:"No token."});
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { return res.status(401).json({ok:false,message:"Invalid or expired token."}); }
}

// ── REGISTER ──────────────────────────────────────
app.post("/api/auth/register", registerLimiter, async (req,res)=>{
  try {
    let {name,email,password} = req.body;
    
    // ← SANITIZE NAME (Step 3 Option 3)
    name = name.trim();
    if(!name||name.length<2) return res.status(400).json({ok:false,message:"Name must be at least 2 characters."});
    // Only allow letters, numbers, spaces, hyphens, apostrophes
    if(!/^[a-zA-Z0-9\s\-']+$/.test(name)) {
      return res.status(400).json({ok:false,message:"Name can only contain letters, numbers, spaces, hyphens, and apostrophes."});
    }
    
    if(!email||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ok:false,message:"Valid email required."});
    if(!password||password.length<6)   return res.status(400).json({ok:false,message:"Password must be at least 6 characters."});

    const em = email.toLowerCase().trim();
    if(db.prepare("SELECT id FROM users WHERE email=?").get(em))
      return res.status(409).json({ok:false,message:"Email already registered."});

    const now  = new Date().toISOString();
    const user = { id:uuid(), name:name, email:em, password_hash:await bcrypt.hash(password,12), avatar_color:pick(COLORS), created_at:now, last_login:now };
    db.prepare("INSERT INTO users VALUES(:id,:name,:email,:password_hash,:avatar_color,:created_at,:last_login)").run(user);
    res.status(201).json({ok:true, message:"Account created.", token:sign(user), user:safe(user)});
  } catch(e){ console.error(e); res.status(500).json({ok:false,message:"Server error."}); }
});

// ── LOGIN ─────────────────────────────────────────
app.post("/api/auth/login", loginLimiter, async (req,res)=>{

// ── ME (protected) ────────────────────────────────
app.get("/api/auth/me", authGuard, (req,res)=>{
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
  if(!u) return res.status(404).json({ok:false,message:"Not found."});
  res.json({ok:true, user:safe(u)});
});

// ── HEALTH ────────────────────────────────────────
app.get("/api/health", (_,res)=> res.json({ok:true, uptime:process.uptime()}));

// ── START ─────────────────────────────────────────
app.listen(PORT, ()=> console.log(`\n🦜  ParrotAI API  →  http://localhost:${PORT}\n`));