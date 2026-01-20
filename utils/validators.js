export function validatePayloadStrict({ name, signature }) {
  if (!name || typeof name !== "string") return "Nombre inválido";
  const cleanName = name.trim();
  if (cleanName.length < 3 || cleanName.length > 80) return "Nombre inválido";

  if (!signature || typeof signature !== "string") return "Firma no válida";

  // ✅ Aceptar SOLO PNG base64
  const prefix = "data:image/png;base64,";
  if (!signature.startsWith(prefix)) return "Firma debe ser PNG";

  const base64 = signature.slice(prefix.length);

  // Validación base64 básica
  if (!/^[A-Za-z0-9+/=\s]+$/.test(base64)) return "Firma corrupta";

  // Tamaño real del archivo (aprox)
  // 4 chars base64 ~ 3 bytes
  const approxBytes = Math.floor((base64.length * 3) / 4);
  const minBytes = Number(process.env.SIGNATURE_MIN_BYTES || 2500);
if (approxBytes < minBytes) return "Firma vacía o demasiado pequeña";

  const maxBytes = Number(process.env.SIGNATURE_MAX_BYTES || 250000); // 250KB por defecto
  if (approxBytes > maxBytes) return "Firma demasiado grande";

  return null;
}