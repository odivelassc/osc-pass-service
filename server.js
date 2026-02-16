const express = require("express");
const { v4: uuidv4 } = require("uuid");
const QRCode = require("qrcode");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const { GoogleAuth } = require("google-auth-library");
const { fetch } = require("undici");

const app = express();
app.use(express.json());

// Phase 1: in-memory store (we'll replace with a DB later)
const store = new Map();
async function getGoogleAccessToken() {
  const auth = new GoogleAuth({
    scopes: ["https://www.googleapis.com/auth/wallet_object.issuer"],
  });
  const client = await auth.getClient();
  const t = await client.getAccessToken();
  return t.token;
}

async function upsertGenericObject({ issuerId, classSuffix, objectSuffix, record }) {
  const accessToken = await getGoogleAccessToken();
  const classId = `${issuerId}.${classSuffix}`;
  const objectId = `${issuerId}.${objectSuffix}`;

  const url = `https://walletobjects.googleapis.com/walletobjects/v1/genericObject/${encodeURIComponent(objectId)}`;

  const body = {
    id: objectId,
    classId,
    state: record.status === "active" ? "ACTIVE" : "INACTIVE",
    cardTitle: { defaultValue: { language: "pt-PT", value: "ODIVELAS SPORTS CLUB" } },
    header: { defaultValue: { language: "pt-PT", value: record.full_name } },
    subheader: { defaultValue: { language: "pt-PT", value: "Cartão de Sócio" } },
    barcode: { type: "QR_CODE", value: record.qr_validation_url },
    textModulesData: [
      { id: "memberNumber", header: "Nº Sócio", body: record.member_number },
      { id: "validUntil", header: "Válido até", body: record.valid_until || "—" }
    ],
    linksModuleData: {
      uris: [{ uri: record.card_public_url, description: "Abrir cartão" }]
    }
  };

  // Try PATCH (update). If 404 then create.
  let r = await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (r.status === 404) {
    r = await fetch("https://walletobjects.googleapis.com/walletobjects/v1/genericObject", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
  }

  // 409 means "already exists" for some operations; treat as OK
  if (!r.ok && r.status !== 409) {
    const txt = await r.text();
    throw new Error(`GenericObject upsert failed: ${r.status} ${txt}`);
  }

  return { classId, objectId };
}

function makeSaveToGoogleWalletUrl({ objectId, classId, origin }) {
  const saPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  const sa = JSON.parse(fs.readFileSync(saPath, "utf8"));

  const claims = {
    aud: "google",
    iss: sa.client_email,
    typ: "savetowallet",
    iat: Math.floor(Date.now() / 1000),
    origins: [origin],
    payload: { genericObjects: [{ id: objectId, classId }] }
  };

  const token = jwt.sign(claims, sa.private_key, { algorithm: "RS256" });
  return `https://pay.google.com/gp/v/save/${token}`;
}
app.post("/api/passes/issue", async (req, res) => {
  const { member_id, full_name, member_number, valid_until, status } = req.body || {};

  if (!member_id || !full_name || !member_number) {
    return res.status(400).json({
      error: "Missing required fields: member_id, full_name, member_number"
    });
  }

  // Idempotent by member_id
  for (const rec of store.values()) {
    if (rec.member_id === member_id) return res.json(rec);
  }

  const token = uuidv4().replaceAll("-", "");
  const baseUrl = process.env.PUBLIC_BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

  const payload = {
    token,
    member_id,
    full_name,
    member_number,
    valid_until: valid_until || null,
    status: status || "active",
    card_public_url: `${baseUrl}/c/${token}`,
    qr_validation_url: `${baseUrl}/v/${token}`,
    apple_pkpass_url: null,
    google_wallet_url: null
  };

  store.set(token, payload);
    // --- Google Wallet: create/update object + build Save URL ---
  try {
    const issuerId = process.env.GOOGLE_ISSUER_ID;
    const origin = process.env.PUBLIC_BASE_URL || "https://osc-pass-service.onrender.com";
    const classSuffix = "MembershipCard"; // <-- from your class id

    if (issuerId) {
      const { classId, objectId } = await upsertGenericObject({
        issuerId,
        classSuffix,
        objectSuffix: payload.token,
        record: payload,
      });

      payload.google_wallet_url = makeSaveToGoogleWalletUrl({ objectId, classId, origin });
    }
  } catch (e) {
    console.error("Google Wallet error:", e);
  }
  res.json(payload);
});

app.get("/v/:token", (req, res) => {
  const record = store.get(req.params.token);
  if (!record) return res.status(404).send("NOT_FOUND");

  const now = new Date();
  const validUntil = record.valid_until ? new Date(record.valid_until) : null;

  if (record.status !== "active") return res.send("NOT_ACTIVE");
  if (validUntil && now > validUntil) return res.send("EXPIRED");
  return res.send("VALID");
});

app.get("/c/:token", async (req, res) => {
  const record = store.get(req.params.token);
  if (!record) return res.status(404).send("Card not found");

  const qrDataUrl = await QRCode.toDataURL(record.qr_validation_url);

  const ua = (req.headers["user-agent"] || "").toLowerCase();
  const isAndroid = ua.includes("android");
  const isIOS = ua.includes("iphone") || ua.includes("ipad") || ua.includes("ipod");

  const primary = isIOS ? "Apple Wallet" : isAndroid ? "Google Wallet" : "Escolher Wallet";

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`
    <html>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Cartão de Sócio - Odivelas SC</title>
        <style>
          body{font-family:Arial;padding:18px;max-width:520px;margin:0 auto}
          .card{border:1px solid #ddd;border-radius:14px;padding:16px}
          .title{font-weight:800;font-size:18px}
          .row{margin-top:10px}
          .label{color:#666;font-size:12px}
          .value{font-size:16px;font-weight:700}
          .badge{display:inline-block;padding:6px 10px;border-radius:999px;background:#f2f2f2;margin-top:8px}
          .btn{display:block;text-align:center;padding:12px 14px;border-radius:10px;background:#000;color:#fff;text-decoration:none;margin-top:12px}
          .btn.secondary{background:#444}
          img.qr{width:160px;height:160px;margin-top:14px}
          .small{color:#666;font-size:12px;margin-top:10px}
        </style>
      </head>
      <body>
        <div class="card">
          <div class="title">ODIVELAS SPORTS CLUB</div>

          <div class="row">
            <div class="label">Nome</div>
            <div class="value">${escapeHtml(record.full_name)}</div>
          </div>

          <div class="row">
            <div class="label">Nº Sócio</div>
            <div class="value">${escapeHtml(record.member_number)}</div>
          </div>

          <div class="row">
            <div class="label">Válido até</div>
            <div class="value">${record.valid_until ? escapeHtml(record.valid_until) : "—"}</div>
          </div>

          <div class="badge">Estado: ${escapeHtml(String(record.status).toUpperCase())}</div>

          <a class="btn" href="${escapeHtml(isAndroid && record.google_wallet_url ? record.google_wallet_url : "#")}"
             onclick="${isAndroid && record.google_wallet_url ? "" : "alert('Google Wallet ainda não está ativo para este cartão')"}">
             ${primary}
             </a>
          <a class="btn secondary" href="${escapeHtml(record.qr_validation_url)}">Testar Validação</a>

          <div class="row">
            <div class="label">QR Code (validação)</div><br/>
            <img class="qr" src="${qrDataUrl}" alt="QR code" />
          </div>

          <div class="small">
            Se estiver no iPhone e o Apple Wallet não abrir a partir do Gmail, abra este link no Safari.
          </div>
        </div>
      </body>
    </html>
  `);
});

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[m]));
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`OSC Pass Service running on ${PORT}`));
