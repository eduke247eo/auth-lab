const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  message: { error: "Хэт олон оролдлого. 1 минутын дараа дахин оролд" }
});

if (!process.env.JWT_SECRET) {
  console.error("JWT_SECRET .env файлд байхгүй байна");
  process.exit(1);
}
const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

const pool = mysql.createPool({
  host: "127.0.0.1", user: "root",
  password: "", database: "auth_db"
});
function createRefreshToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashRefreshToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function setAuthCookies(res, accessToken, refreshToken) {
  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/"
  };

  res.cookie("accessToken", accessToken, {
    ...cookieOptions,
    maxAge: 15 * 60 * 1000
  });

  res.cookie("refreshToken", refreshToken, {
    ...cookieOptions,
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function clearAuthCookies(res) {
  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/"
  };

  res.clearCookie("accessToken", cookieOptions);
  res.clearCookie("refreshToken", cookieOptions);
}
app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (typeof email !== "string" || !email.includes("@")) {
      return res.status(400).json({ error: "И-мэйл буруу байна" });
    }
    if (
  typeof password !== "string" ||
  password.length < 8 ||
  Buffer.byteLength(password, "utf8") > 72 ||
  !/[A-Z]/.test(password) ||
  !/[a-z]/.test(password) ||
  !/[0-9]/.test(password)
) {
  return res.status(400).json({
    error: "Нууц үг хамгийн багадаа 8 тэмдэгттэй, том үсэг, жижиг үсэг, тоо агуулсан байх ёстой"
  });
}
    const hash = await bcrypt.hash(password, 10);
    const [r] = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)",
      [email.toLowerCase(), hash]
    );
    res.status(201).json({ id: r.insertId, email: email.toLowerCase() });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "Энэ и-мэйл бүртгэлтэй байна" });
    }
    console.error(err);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});
app.post("/api/login", loginLimiter,async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "И-мэйл, нууц үг шаардлагатай" });
    }
    const [rows] = await pool.query(
      "SELECT id, email, password_hash, role FROM users WHERE email = ?",
      [email.toLowerCase()]
    );
    const user = rows[0];
    const ok = user && await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "И-мэйл эсвэл нууц үг буруу" });
    }
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );
    res.cookie("accessToken", token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  maxAge: 15 * 60 * 1000,
  path: "/"
});

res.json({ message: "Амжилттай нэвтэрлээ" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});
function requireAuth(req, res, next) {
  const token = req.cookies.accessToken;

  if (!token) {
    return res.status(401).json({
      error: "Токен алга"
    });
  }

  jwt.verify(
    token,
    process.env.JWT_SECRET,
    { algorithms: ["HS256"] },
    (err, payload) => {
      if (err) {
        return res.status(403).json({
          error: "Хүчингүй токен"
        });
      }

      req.user = payload;
      next();
    }
  );
}
app.post("/api/change-password", requireAuth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body || {};

    
    if (
      typeof oldPassword !== "string" ||
      typeof newPassword !== "string"
    ) {
      return res.status(400).json({
        error: "Хуучин болон шинэ нууц үг шаардлагатай"
      });
    }

    
    if (
      newPassword.length < 8 ||
      Buffer.byteLength(newPassword, "utf8") > 72
    ) {
      return res.status(400).json({
        error: "Шинэ нууц үг 8-аас доошгүй, 72 byte-аас ихгүй байна"
      });
    }

    
    const [rows] = await pool.query(
      "SELECT password_hash FROM users WHERE id = ?",
      [req.user.userId]
    );

    if (!rows[0]) {
      return res.status(404).json({
        error: "Хэрэглэгч олдсонгүй"
      });
    }

    
    const isValid = await bcrypt.compare(
      oldPassword,
      rows[0].password_hash
    );

    if (!isValid) {
      return res.status(401).json({
        error: "Хуучин нууц үг буруу"
      });
    }

    
    const newHash = await bcrypt.hash(newPassword, 10);

    
    await pool.query(
      "UPDATE users SET password_hash = ? WHERE id = ?",
      [newHash, req.user.userId]
    );

    return res.status(200).json({
      message: "Нууц үг амжилттай солигдлоо"
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: "Серверийн алдаа"
    });
  }
});
function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: "Эрх хүрэхгүй" });
    }
    next();
  };
}

app.get("/api/profile", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, email, role, created_at FROM users WHERE id = ?",
      [req.user.userId]
    );
    if (!rows[0]) {
      return res.status(404).json({ error: "Хэрэглэгч олдсонгүй" });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

app.get("/api/admin", requireAuth, requireRole("admin"), (req, res) => {
  res.json({ message: "Админ хэсэг. Хэрэглэгч №" + req.user.userId });
});
app.post("/api/refresh", async (req, res) => {
  const token = req.cookies.refreshToken;

  if (!token) {
    return res.status(401).json({
      error: "Refresh token алга"
    });
  }

  let connection;

  try {
    const tokenHash = hashRefreshToken(token);

    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [rows] = await connection.query(
      `SELECT id, user_id
       FROM refresh_tokens
       WHERE token_hash = ? AND expires_at > NOW()`,
      [tokenHash]
    );

    if (!rows.length) {
      await connection.rollback();
      clearAuthCookies(res);

      return res.status(401).json({
        error: "Refresh token хүчингүй эсвэл хугацаа дууссан"
      });
    }

    const storedToken = rows[0];

    // Хуучин refresh token-ийг хүчингүй болгоно.
    const [deleted] = await connection.query(
      "DELETE FROM refresh_tokens WHERE id = ?",
      [storedToken.id]
    );

    if (deleted.affectedRows !== 1) {
      await connection.rollback();
      clearAuthCookies(res);

      return res.status(401).json({
        error: "Refresh token хүчингүй"
      });
    }

    const [users] = await connection.query(
      "SELECT id, role FROM users WHERE id = ?",
      [storedToken.user_id]
    );

    if (!users.length) {
      await connection.rollback();
      clearAuthCookies(res);

      return res.status(401).json({
        error: "Хэрэглэгч олдсонгүй"
      });
    }

    const user = users[0];

    const newAccessToken = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m", algorithm: "HS256" }
    );

    const newRefreshToken = createRefreshToken();
    const newHash = hashRefreshToken(newRefreshToken);

    await connection.query(
      `INSERT INTO refresh_tokens
       (user_id, token_hash, expires_at)
       VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))`,
      [user.id, newHash]
    );

    await connection.commit();

    setAuthCookies(res, newAccessToken, newRefreshToken);

    res.json({ message: "Token амжилттай шинэчлэгдлээ" });
  } catch (err) {
    if (connection) {
      await connection.rollback();
    }

    console.error(err);
    res.status(500).json({ error: "Серверийн алдаа" });
  } finally {
    if (connection) connection.release();
  }
});
app.post("/api/logout", async (req, res) => {
  try {
    const token = req.cookies.refreshToken;

    if (token) {
      const tokenHash = hashRefreshToken(token);

      await pool.query(
        "DELETE FROM refresh_tokens WHERE token_hash = ?",
        [tokenHash]
      );
    }

    clearAuthCookies(res);

    res.json({ message: "Амжилттай гарлаа" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});
app.listen(3000, () => console.log("http://localhost:3000"));