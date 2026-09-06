import dotenv from "dotenv";
dotenv.config();
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import slowDown from "express-slow-down";

import { sendSignatureEmail } from "./utils/mailer.js";
import { validatePayloadStrict } from "./utils/validators.js";
import {
  initTenants,
  getTenantByOrigin,
  allowedOrigins as tenantOrigins,
  normalizeOrigin,
  currentMode,
} from "./utils/tenants.js";

// ✅ Config de tenants ANTES de construir el app: si el mapeo está mal
// (JSON inválido, origen duplicado, correo sin configurar) el proceso muere
// aquí y App Runner conserva la versión anterior en producción.
initTenants();

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

// ✅ CORS estricto. La fuente de verdad es config/tenants.json: agregar un tenant
// habilita su CORS solo. ALLOWED_ORIGINS queda como aditivo opcional (herramientas,
// entornos de prueba) — puede quedar vacío.
const allowedOrigins = new Set([
  ...tenantOrigins(),
  ...(process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(normalizeOrigin)
    .filter(Boolean),
]);

const corsOptions = {
  origin: (origin, cb) => {
    // curl/postman/healthchecks: los deja pasar el CORS, pero /send-signature
    // igual los rechaza en resolveTenant por no tener Origin.
    if (!origin) return cb(null, true);

    // ✅ Mismo criterio que resolveTenant (barra final, mayúsculas): si las dos
    // capas normalizaran distinto, un Origin podría pasar una y morir en la otra.
    if (allowedOrigins.has(normalizeOrigin(origin))) return cb(null, true);

    console.warn("⛔ CORS bloqueó el Origin:", origin);
    return cb(new Error(`CORS blocked: ${origin}`), false);
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-Signature-Token"],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ✅ Quién recibe esta firma. El Origin lo pone el navegador y el cliente no puede
// falsificarlo desde la página; un curl sí, pero solo puede elegir entre los origins
// ya configurados — nunca un destino nuevo.
function resolveTenant(req, res, next) {
  const tenant = getTenantByOrigin(req.headers.origin);

  if (!tenant) {
    console.warn("⛔ Firma rechazada. Origin no reconocido:", req.headers.origin || "(ausente)");
    return res.status(403).json({ success: false, message: "Origen no autorizado" });
  }

  req.tenant = tenant;
  next();
}

// ✅ Cuotas por tenant + IP: un subdominio con mucho tráfico no consume la cuota de
// otro cuando comparten IP de salida (oficina, VPN corporativa).
// ⚠️ express-rate-limit v8 exige envolver la IP con ipKeyGenerator en cualquier
// keyGenerator propio, o falla con IPv6.
const tenantIpKey = (req) => `${req.tenant?.id || "sin-tenant"}:${ipKeyGenerator(req.ip)}`;

// ✅ Anti-spam: rate limit
const sendSignatureLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: Number(process.env.RATE_LIMIT_MAX || 10), // 10 envíos por tenant+IP / 15 min
  keyGenerator: tenantIpKey,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Demasiados intentos. Intenta más tarde." },
});

// ✅ Anti-spam: slow down (retrasa a partir de N requests)
const sendSignatureSpeedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: Number(process.env.SLOWDOWN_AFTER || 5),
  delayMs: () => Number(process.env.SLOWDOWN_DELAY_MS || 800), // 0.8s extra por request
  keyGenerator: tenantIpKey,
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
  resolveTenant,
  sendSignatureLimiter,
  sendSignatureSpeedLimiter,
  async (req, res) => {
    try {
      const { name, idNumber, signature } = req.body;

      const error = validatePayloadStrict({ name, signature });
      if (error) return res.status(400).json({ success: false, message: error });

      const timestamp = new Date().toLocaleString("es-CO");

      await sendSignatureEmail({ name, idNumber, signature, timestamp, tenant: req.tenant });

      console.log(`✉️  Firma enviada. Tenant: ${req.tenant.id} (${req.tenant.label})`);

      return res.json({ success: true, message: "Firma enviada correctamente" });
    } catch (err) {
      // ❗️El detalle queda en el log, no en la respuesta: err.message puede traer
      // el correo destino o el nombre de una variable de entorno.
      console.error(`ERROR enviando firma. Tenant: ${req.tenant?.id || "?"} —`, err);
      return res.status(500).json({
        success: false,
        message: "No se pudo enviar la firma. Intenta más tarde.",
      });
    }
  }
);

app.use((err, req, res, next) => {
  // Errores típicos de CORS que tú mismo generas
  if (err?.message?.startsWith("CORS")) {
    return res.status(403).json({ success: false, message: err.message });
  }
  console.error("UNHANDLED ERROR:", err);
  return res.status(500).json({ success: false, message: "Server error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} — modo ${currentMode()}`);
});
