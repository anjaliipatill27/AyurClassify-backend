const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./db");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

// Home route
app.get("/", (req, res) => {
  res.send("AyurClassify Backend is Running!");
});

// Check server and database
app.get("/api/status", async (req, res) => {
  try {
    await db.execute("SELECT 1");
    res.json({
      server: "Running",
      database: "Connected"
    });
  } catch (error) {
    res.status(500).json({
      server: "Running",
      database: "Disconnected"
    });
  }
});

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      !name?.trim() ||
      !email?.trim() ||
      typeof password !== "string" ||
      password.length < 6
    ) {
      return res.status(400).json({
        message: "Enter name, email and password (minimum 6 characters)."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const [existing] = await db.execute(
      "SELECT id FROM users WHERE email = ?",
      [cleanEmail]
    );

    if (existing.length > 0) {
      return res.status(409).json({
        message: "Email is already registered. Please login."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const [result] = await db.execute(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
      [name.trim(), cleanEmail, passwordHash]
    );

    res.status(201).json({
      message: "Registration successful!",
      userId: result.insertId
    });
  } catch (error) {
    console.error("Register error:", error.message);
    res.status(500).json({
      message: "Registration failed."
    });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "Enter email and password."
      });
    }

    const [users] = await db.execute(
      "SELECT id, name, email, password_hash FROM users WHERE email = ?",
      [email.trim().toLowerCase()]
    );

    if (users.length === 0) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    const user = users[0];

    const passwordMatch = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatch) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({
      message: "Login successful!",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({
      message: "Login failed."
    });
  }
});

// VERIFY LOGIN TOKEN
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      message: "Please login first."
    });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Session expired or token is invalid. Please login again."
    });
  }
}

// SAVE CLASSIFICATION RESULT
app.post("/api/classify", authenticateToken, async (req, res) => {
  try {
    const { vata, pitta, kapha, category } = req.body;

    if (
      !Number.isInteger(vata) || vata < 0 ||
      !Number.isInteger(pitta) || pitta < 0 ||
      !Number.isInteger(kapha) || kapha < 0 ||
      !["Vata", "Pitta", "Kapha", "Mixed / Tie"].includes(category)
    ) {
      return res.status(400).json({
        message: "Invalid classification data."
      });
    }

    // User ID comes from the verified login token
    const userId = req.user.id;

    const [result] = await db.execute(
      `INSERT INTO classification_results
       (user_id, vata_score, pitta_score, kapha_score, result_category)
       VALUES (?, ?, ?, ?, ?)`,
      [userId, vata, pitta, kapha, category]
    );

    res.status(201).json({
      message: "Classification result saved!",
      resultId: result.insertId
    });
  } catch (error) {
    console.error("Classification save error:", error.message);
    res.status(500).json({
      message: "Could not save classification result."
    });
  }
});

app.get("/api/history", authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.execute(
      `SELECT id, vata_score, pitta_score, kapha_score,
              result_category, created_at
       FROM classification_results
       WHERE user_id = ?
       ORDER BY id DESC`,
      [req.user.id]
    );

    res.json(rows);
  } catch (error) {
    console.error("History error:", error.message);
    res.status(500).json({
      message: "Could not load classification history."
    });
  }
});

app.get("/api/dashboard", authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.execute(
      `SELECT
         COUNT(*) AS totalResults,
         MAX(created_at) AS lastClassification
       FROM classification_results
       WHERE user_id = ?`,
      [req.user.id]
    );

    res.json(rows[0]);
  } catch (error) {
    console.error("Dashboard error:", error.message);
    res.status(500).json({
      message: "Could not load dashboard."
    });
  }
});
// START SERVER
const PORT = 3000;

app.listen(PORT, () => {
  console.log(`AyurClassify server running at http://localhost:${PORT}`);
});