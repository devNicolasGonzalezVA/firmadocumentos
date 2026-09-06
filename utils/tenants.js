import { readFileSync } from "node:fs";

// ✅ Mapa subdominio -> destino de correo.
// El archivo JSON va a git; los correos NO. Cada tenant declara el NOMBRE de la
// variable de entorno que contiene su destino, nunca el correo en sí.
const CONFIG_URL = new URL("../config/tenants.json", import.meta.url);

// Convención de respaldo, para tenants que no declaren "emailToEnv":
// id "mi-cliente" -> TENANT_MI_CLIENTE_EMAIL_TO
const ENV_PREFIX = "TENANT_";
const ENV_SUFFIX = "_EMAIL_TO";

// ids en minúscula, para que el nombre de variable derivado sea predecible
const ID_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;

let byOrigin = null;

// ✅ Por defecto asumimos PRODUCCIÓN (modo estricto). El modo cómodo de desarrollo
// hay que pedirlo explícito con NODE_ENV=development en el .env local.
// Al revés —asumir dev salvo que digan lo contrario— un olvido de configuración en
// App Runner dejaría el servidor público en modo permisivo y sin ningún síntoma.
const DEV_MODES = new Set(["development", "dev", "local", "test"]);

function isDev() {
  return DEV_MODES.has(String(process.env.NODE_ENV || "").trim().toLowerCase());
}

export function currentMode() {
  return isDev() ? "desarrollo" : "producción";
}

// ✅ "https://the.documentosfirma.com/" -> "https://the.documentosfirma.com"
export function normalizeOrigin(value) {
  if (!value || typeof value !== "string") return null;
  try {
    return new URL(value.trim()).origin.toLowerCase(); // sin barra final
  } catch {
    return null;
  }
}

// ✅ Nombre de la variable de entorno cuando el tenant no declara 'emailToEnv'
export function envNameForTenant(id) {
  return `${ENV_PREFIX}${String(id).toUpperCase().replaceAll("-", "_")}${ENV_SUFFIX}`;
}

// Validación mínima: no queremos adivinar el RFC 5322, solo atajar un valor
// obviamente mal puesto (una URL, un nombre suelto, un espacio de más).
function looksLikeEmail(value) {
  return /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test(value);
}

// ✅ Resuelve el destino leyendo SIEMPRE de process.env.
// En modo producción, si falta la variable no arrancamos (mejor un deploy fallido
// que firmas al buzón equivocado). Solo en modo desarrollo caemos a EMAIL_TO con un
// aviso, para no obligar a definir el correo de cada cliente al levantar el server.
function resolveEmailTo(tenant) {
  if (tenant.emailTo) {
    throw new Error(
      `Tenant "${tenant.id}": el correo no puede ir en tenants.json (el archivo está en git). ` +
      `Quita "emailTo" y define la variable de entorno ${envNameForTenant(tenant.id)}.`
    );
  }

  const envName = tenant.emailToEnv || envNameForTenant(tenant.id);
  if (typeof envName !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(envName)) {
    throw new Error(`Tenant "${tenant.id}": "emailToEnv" inválido (${envName})`);
  }

  const declarada = Object.prototype.hasOwnProperty.call(process.env, envName);
  let value = (process.env[envName] || "").trim();

  if (!value && isDev() && envName !== "EMAIL_TO") {
    value = (process.env.EMAIL_TO || "").trim();
    if (value) {
      console.warn(
        `⚠️  Tenant "${tenant.id}": ${envName} no está definida. ` +
        `Usando EMAIL_TO (solo desarrollo).`
      );
    }
  }

  if (!value) {
    throw new Error(
      declarada
        ? `Tenant "${tenant.id}": ${envName} existe en el entorno pero está vacía.`
        : `Tenant "${tenant.id}": correo destino no configurado. Define ${envName} en el entorno.`
    );
  }
  if (!looksLikeEmail(value)) {
    throw new Error(`Tenant "${tenant.id}": ${envName} no parece un correo válido.`);
  }

  return value;
}

function build() {
  let raw;
  try {
    raw = JSON.parse(readFileSync(CONFIG_URL, "utf8"));
  } catch (err) {
    throw new Error(`No se pudo leer config/tenants.json: ${err.message}`);
  }

  const list = Array.isArray(raw?.tenants) ? raw.tenants : null;
  if (!list) throw new Error('config/tenants.json debe tener un arreglo "tenants"');

  const map = new Map();
  const seenIds = new Set();

  for (const t of list) {
    if (!t || typeof t !== "object") throw new Error("Entrada de tenant inválida");

    // ❗️Las entradas marcadas dev solo existen en modo desarrollo.
    if (t.dev && !isDev()) continue;

    if (!ID_RE.test(t.id || "")) {
      throw new Error(`Tenant con id inválido: ${JSON.stringify(t.id)} (a-z, 0-9, guion)`);
    }
    if (seenIds.has(t.id)) throw new Error(`Tenant duplicado: ${t.id}`);
    seenIds.add(t.id);

    if (!t.label || typeof t.label !== "string") {
      throw new Error(`Tenant "${t.id}": falta "label"`);
    }

    const origins = (Array.isArray(t.origins) ? t.origins : [])
      .map(normalizeOrigin)
      .filter(Boolean);
    if (origins.length === 0) throw new Error(`Tenant "${t.id}": sin origins válidos`);

    const emailTo = resolveEmailTo(t);

    for (const origin of origins) {
      // ❗️Un origen duplicado significaría firmas al correo equivocado: no arrancamos.
      const clash = map.get(origin);
      if (clash) {
        throw new Error(
          `Origin duplicado en tenants.json: ${origin} (tenants "${clash.id}" y "${t.id}")`
        );
      }
      map.set(origin, Object.freeze({ id: t.id, label: t.label, emailTo, origin }));
    }
  }

  if (map.size === 0) throw new Error("tenants.json no define ningún tenant válido");
  return map;
}

function tenantEnvVarsPresentes() {
  return Object.keys(process.env)
    .filter(k => k.startsWith(ENV_PREFIX) && k.endsWith(ENV_SUFFIX))
    .sort();
}

// ✅ Se llama una sola vez, al arrancar, ANTES de abrir el puerto.
export function initTenants() {
  try {
    byOrigin = build();
  } catch (err) {
    const presentes = tenantEnvVarsPresentes();
    console.error("❌ No se pudo cargar la configuración de tenants.");
    console.error("   Motivo:", err.message);
    console.error("   NODE_ENV:", JSON.stringify(process.env.NODE_ENV ?? null), `-> modo ${currentMode()}`);
    console.error("   Variables TENANT_*_EMAIL_TO que ve el proceso:",
      presentes.length ? presentes.join(", ") : "(NINGUNA)");
    console.error("   EMAIL_TO definida:", process.env.EMAIL_TO ? "sí" : "no");
    console.error("   Total de variables de entorno visibles:", Object.keys(process.env).length);
    throw err; // ❗️seguimos sin arrancar: el diagnóstico no relaja el fail fast
  }
  const ids = [...new Set([...byOrigin.values()].map(t => t.id))];
  console.log(`✅ Tenants cargados en modo ${currentMode()} (${ids.length}):`, ids.join(", "));
  return byOrigin;
}

export function getTenantByOrigin(origin) {
  if (!byOrigin) throw new Error("initTenants() no fue llamado");
  const key = normalizeOrigin(origin);
  return key ? byOrigin.get(key) || null : null;
}

// ✅ Fuente única de verdad para el CORS del server.
export function allowedOrigins() {
  if (!byOrigin) throw new Error("initTenants() no fue llamado");
  return [...byOrigin.keys()];
}

// Útil para logs y para /health; nunca expone el correo destino.
export function listTenants() {
  if (!byOrigin) throw new Error("initTenants() no fue llamado");
  const out = new Map();
  for (const t of byOrigin.values()) {
    if (!out.has(t.id)) out.set(t.id, { id: t.id, label: t.label, origins: [] });
    out.get(t.id).origins.push(t.origin);
  }
  return [...out.values()];
}
