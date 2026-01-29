require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const Stripe = require("stripe");

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.use(cors());
app.use(express.json());

/* =========================
   HELPERS
========================= */

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No autorizado" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
}

async function hasAccess(user) {
  if (user.is_admin) return true;
  if (user.free_access) return true;
  if (user.subscription_active) return true;
  if (user.trial_end && new Date(user.trial_end) > new Date()) return true;
  return false;
}

/* =========================
   AUTH
========================= */

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);
  const trialEnd = new Date();
  trialEnd.setDate(trialEnd.getDate() + 7);

  const isAdmin = email === process.env.ADMIN_EMAIL;

  try {
    const result = await pool.query(
      `INSERT INTO users
       (name, email, password, trial_end, is_admin, free_access)
       VALUES ($1,$2,$3,$4,$5,$5)
       RETURNING *`,
      [name, email, hashed, trialEnd, isAdmin]
    );

    res.json({
      token: generateToken(result.rows[0]),
      user: result.rows[0]
    });
  } catch (err) {
    res.status(400).json({ error: "Usuario ya existe" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query(
    "SELECT * FROM users WHERE email=$1",
    [email]
  );
  const user = result.rows[0];

  if (!user) return res.status(400).json({ error: "Usuario no existe" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: "Password incorrecto" });

  res.json({
    token: generateToken(user),
    user
  });
});

/* =========================
   ACCESS CHECK
========================= */

app.get("/me", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM users WHERE id=$1",
    [req.user.id]
  );
  const user = result.rows[0];

  const access = await hasAccess(user);

  res.json({
    user,
    access,
    trial_active:
      user.trial_end && new Date(user.trial_end) > new Date()
  });
});

/* =========================
   STRIPE
========================= */

app.post("/create-checkout", auth, async (req, res) => {
  const userRes = await pool.query(
    "SELECT * FROM users WHERE id=$1",
    [req.user.id]
  );
  const user = userRes.rows[0];

  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    payment_method_types: ["card"],
    customer_email: user.email,
    line_items: [
      {
        price: process.env.STRIPE_PRICE_ID,
        quantity: 1
      }
    ],
    success_url: "https://tusitio.com/success",
    cancel_url: "https://tusitio.com/cancel"
  });

  res.json({ url: session.url });
});

/* =========================
   STRIPE WEBHOOK
========================= */

app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const event = req.body;

    if (event.type === "checkout.session.completed") {
      const email = event.data.object.customer_email;

      await pool.query(
        `UPDATE users
         SET subscription_active=true
         WHERE email=$1`,
        [email]
      );
    }

    res.json({ received: true });
  }
);

/* =========================
   ADMIN
========================= */

app.post("/admin/free-access", auth, async (req, res) => {
  const admin = await pool.query(
    "SELECT * FROM users WHERE id=$1",
    [req.user.id]
  );

  if (!admin.rows[0]?.is_admin)
    return res.status(403).json({ error: "No autorizado" });

  const { email } = req.body;

  await pool.query(
    "UPDATE users SET free_access=true WHERE email=$1",
    [email]
  );

  res.json({ ok: true });
});

/* =========================
   PROTECTED EXAMPLE
========================= */

app.get("/analyze-food", auth, async (req, res) => {
  const userRes = await pool.query(
    "SELECT * FROM users WHERE id=$1",
    [req.user.id]
  );

  if (!(await hasAccess(userRes.rows[0]))) {
    return res.status(403).json({
      error: "Trial vencido o suscripción requerida"
    });
  }

  res.json({
    food: "Pollo con arroz",
    calories: 520,
    protein: 38,
    carbs: 45,
    fat: 12
  });
});

/* ========================= */

app.listen(process.env.PORT, () =>
  console.log("Backend NutriApp activo 🚀")
);

        
