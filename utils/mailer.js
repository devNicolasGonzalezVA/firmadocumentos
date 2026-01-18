import nodemailer from "nodemailer";

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;

  const user = process.env.EMAIL_USER;
  const pass = process.env.EMAIL_PASS;

  if (!user || !pass) {
    throw new Error("EMAIL_USER/EMAIL_PASS no configurados");
  }

  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user, pass },
  });

  return transporter;
}

export async function sendSignatureEmail({ name, idNumber, signature, timestamp }) {
  const t = getTransporter();

  const base64Data = signature.split(";base64,").pop();
  const buffer = Buffer.from(base64Data, "base64");

  await t.sendMail({
    from: `"Firma Digital" <${process.env.EMAIL_USER}>`,
    to: process.env.EMAIL_TO,
    subject: "Nueva firma recibida",
    html: `
      <h2>Nueva Firma Digital</h2>
      <p><strong>Nombre:</strong> ${escapeHtml(name)}</p>
      ${idNumber ? `<p><strong>ID:</strong> ${escapeHtml(idNumber)}</p>` : ""}
      <p><strong>Fecha y hora:</strong> ${escapeHtml(timestamp || "")}</p>
    `,
    attachments: [{ filename: "firma.png", content: buffer }],
  });
}

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}