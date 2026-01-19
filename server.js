import dotenv from "dotenv";
dotenv.config();
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import slowDown from "express-slow-down";

import { sendSignatureEmail } from "./utils/mailer.js";
import { validatePayloadStrict } from "./utils/validators.js";




const app = express();

// ✅ Si deployas detrás de proxy (Render, Railway, ALB, Cloudflare, etc.)
// Esto hace que req.ip sea la IP real del cliente.
app.set("trust proxy", 1);

// ✅ Seguridad básica headers
app.use(helmet({
    // ✅ HSTS: fuerza HTTPS (solo si tu API ya está 100% en HTTPS)
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: false },

    // ❗️Si tu API devuelve imágenes base64 o cosas "raras", esto normalmente NO afecta.
    // Pero CSP puede romper frontends si lo haces muy estricto; para APIs suele estar OK desactivarlo.
    contentSecurityPolicy: false,
  }));

// ✅ Body limit (ajústalo: 700kb suele ir bien para firmas PNG de canvas)
app.use(express.json({ limit: process.env.JSON_LIMIT || "700kb" }));

// ✅ CORS estricto (solo dominios permitidos)
const allowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean)
);

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // curl/postman/healthchecks
    if (allowedOrigins.size === 0) return cb(new Error("CORS not configured"), false);
    if (allowedOrigins.has(origin)) return cb(null, true);
    return cb(new Error(`CORS blocked: ${origin}`), false);
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-Signature-Token"],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ✅ Anti-spam: rate limit
const sendSignatureLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: Number(process.env.RATE_LIMIT_MAX || 10), // 10 envíos por IP / 15 min
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Demasiados intentos. Intenta más tarde." },
});

// ✅ Anti-spam: slow down (retrasa a partir de N requests)
const sendSignatureSpeedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: Number(process.env.SLOWDOWN_AFTER || 5),
  delayMs: () => Number(process.env.SLOWDOWN_DELAY_MS || 800), // 0.8s extra por request
});

// ✅ (Opcional) Token secreto anti-bot
function requireSignatureToken(req, res, next) {
  const required = process.env.SIGNATURE_TOKEN;
  if (!required) return next(); // si no está configurado, no bloquea

  const provided = req.header("X-Signature-Token");
  if (provided !== required) {
    return res.status(401).json({ success: false, message: "No autorizado" });
  }
  next();
}

// Health check
app.get("/health", (req, res) => res.json({ ok: true }));

// Endpoint protegido
app.post(
  "/send-signature",
  requireSignatureToken,
  sendSignatureLimiter,
  sendSignatureSpeedLimiter,
  async (req, res) => {
    try {
      const { name, idNumber, signature } = req.body;

      const error = validatePayloadStrict({ name, signature });
      if (error) return res.status(400).json({ success: false, message: error });

      const timestamp = new Date().toLocaleString("es-CO");

      await sendSignatureEmail({ name, idNumber, signature, timestamp });

      return res.json({ success: true, message: "Firma enviada correctamente" });
    } catch (err) {
      console.error(err);
      return res.status(500).json({
    success: false,
    message: err?.message || "Server error"});
    }
  }
);

app.use((err, req, res, next) => {
  // Errores típicos de CORS que tú mismo generas
  if (err?.message?.startsWith("CORS")) {
    return res.status(403).json({ success: false, message: err.message });
  }
  if (err?.message === "CORS not configured") {
    return res.status(500).json({ success: false, message: "ALLOWED_ORIGINS no configurado en el servidor" });
  }
  console.error("UNHANDLED ERROR:", err);
  return res.status(500).json({ success: false, message: "Server error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});