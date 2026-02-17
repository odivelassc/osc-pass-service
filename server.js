const express = require("express");
const { v4: uuidv4 } = require("uuid");
const QRCode = require("qrcode");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const { GoogleAuth } = require("google-auth-library");
const { fetch } = require("undici");

const app = express();
app.use(express.json());

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[m]));
}

function computeValidationState(record) {
  if (!record) return { state: "INVALID", label: "Inválido" };

  if (record.status !== "active") {
    return { state: "INACTIVE", label: "Inativo" };
  }

  if (record.valid_until) {
    const now = new Date();
    const validUntil = new Date(record.valid_until);

    if (validUntil < now) {
      return { state: "EXPIRED", label: "Expirado" };
    }
  }

  return { state: "VALID", label: "Válido" };
}

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
  subheader: { defaultValue: { language: "pt-PT", value: "Membro" } }, 
  barcode: { 
    type: "QR_CODE", 
    value: record.qr_validation_url,
    renderOptions: { appearance: "NON_CONFORMANT" } 
  },
  textModulesData: [
    { id: "memberNumber", header: "N", body: String(record.member_number) },
    { id: "type", header: "Tipo", body: "SÓCIO FUNDADOR" },
    { id: "validUntil", header: "Válido até", body: record.valid_until || "—" }
  ],
  heroImage: {
    sourceUri: { uri: process.env.OSC_HERO_URL || "" },
    contentDescription: { defaultValue: { language: "pt-PT", value: "OSC Banner" } }
  }
};

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
  try {
    const issuerId = process.env.GOOGLE_ISSUER_ID;
    const origin = process.env.PUBLIC_BASE_URL || "https://osc-pass-service.onrender.com";
    const classSuffix = "MembershipCard";

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

app.get("/admin/env-check", (req, res) => {
  res.json({
    hasEnvAdminToken: !!process.env.ADMIN_TOKEN,
    envLen: process.env.ADMIN_TOKEN ? String(process.env.ADMIN_TOKEN).length : 0
  });
});

app.get("/v/:token", (req, res) => {
  const record = store.get(req.params.token);

  const state = computeValidationState(record);
  const isValid = state === "VALID";

  const title = isValid ? "VÁLIDO" : "NÃO VÁLIDO";
  const subtitle =
    state === "VALID" ? "Cartão ativo" :
    state === "NOT_ACTIVE" ? "Cartão desativado" :
    state === "EXPIRED" ? "Cartão expirado" :
    "Cartão não encontrado";

  const logoUrl =
    process.env.OSC_FOOTER_LOGO_URL ||
    process.env.OSC_LOGO_URL ||
    "";

  const clubName = "ODIVELAS SPORTS CLUB";

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${escapeHtml(clubName)} — Validação</title>
  <style>
    :root{
      --bg:#000;
      --text:#fff;
      --muted:rgba(255,255,255,.70);
      --yellow:#f4c400;
      --red:#ff3b30;
      --ring:rgba(255,255,255,.10);
    }
    body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
    .wrap{min-height:100vh;display:grid;place-items:center;padding:20px;}
    .panel{width:min(560px, 96vw);text-align:center;padding:24px 18px 28px;}
    .top{display:block;opacity:.95;margin-bottom:10px}
    .club{font-weight:900;letter-spacing:.08em;font-size:12px;color:rgba(255,255,255,.60)}
    .icon{margin:18px auto 12px;width:128px;height:128px}
    .ring{stroke:var(--ring);stroke-width:10;fill:none}
    .ok{stroke:var(--yellow);stroke-width:10;fill:none;stroke-linecap:round;stroke-linejoin:round;
      stroke-dasharray:160;stroke-dashoffset:160;animation:draw .9s ease forwards;
    }
    .bad{stroke:var(--red);stroke-width:10;fill:none;stroke-linecap:round;
      stroke-dasharray:160;stroke-dashoffset:160;animation:draw .9s ease forwards;
    }
    @keyframes draw{to{stroke-dashoffset:0}}
    .title{
      font-size:54px;font-weight:1000;margin:0;letter-spacing:.02em;
      color:${isValid ? "var(--yellow)" : "var(--red)"};
    }
    .sub{margin-top:10px;color:var(--muted);font-size:18px;font-weight:700}
    .pulse{
      margin:18px auto 0;width:12px;height:12px;border-radius:999px;
      background:${isValid ? "var(--yellow)" : "var(--red)"};
      box-shadow:0 0 0 0 ${isValid ? "rgba(244,196,0,.55)" : "rgba(255,59,48,.45)"};
      animation:pulse 1.4s infinite;
    }
    @keyframes pulse{
      0%{box-shadow:0 0 0 0 ${isValid ? "rgba(244,196,0,.55)" : "rgba(255,59,48,.45)"}}
      70%{box-shadow:0 0 0 18px rgba(0,0,0,0)}
      100%{box-shadow:0 0 0 0 rgba(0,0,0,0)}
    }
    .hint{margin-top:16px;color:rgba(255,255,255,.42);font-size:12px}
    .brandLogo{max-width:280px;height:auto;display:block;margin:0 auto 10px;}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="panel">
      <div class="top">
        ${
          logoUrl
            ? `<img class="brandLogo" src="${escapeHtml(logoUrl)}" alt="Odivelas Sports Club" />`
            : ""
        }
      </div>

      <svg class="icon" viewBox="0 0 160 160" aria-hidden="true">
        <circle class="ring" cx="80" cy="80" r="56"></circle>
        ${
          isValid
            ? `<path class="ok" d="M52 82 L72 102 L112 62"></path>`
            : `<path class="bad" d="M60 60 L100 100"></path>
               <path class="bad" d="M100 60 L60 100"></path>`
        }
      </svg>

      <h1 class="title">${title}</h1>
      <div class="sub">${escapeHtml(subtitle)}</div>
      <div class="pulse"></div>

      <div class="hint">Validação oficial — Odivelas Sports Club</div>
    </div>
  </div>
</body>
</html>
`);
});

app.get("/v/:token.txt", (req, res) => {
  const record = store.get(req.params.token);
  const state = computeValidationState(record);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.send(state);
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

app.get("/admin/ping", (req, res) => {
  res.json({
    ok: true,
    hasEnvAdminToken: !!process.env.ADMIN_TOKEN,
    headerPresent: !!req.get("x-admin-token"),
    headerPresentAlt: !!req.get("x-admin-token".toLowerCase()),
    envLen: process.env.ADMIN_TOKEN ? String(process.env.ADMIN_TOKEN).length : 0,
    headerLen: req.get("x-admin-token") ? String(req.get("x-admin-token")).length : 0
  });
});

app.post("/admin/google-wallet/brand-class", async (req, res) => {
  try {
    const token = (req.get("x-admin-token") || "").trim();
    const adminToken = String(process.env.ADMIN_TOKEN || "").trim();
    if (!adminToken || token !== adminToken) return res.status(401).json({ error: "Unauthorized" });

    const issuerId = String(process.env.GOOGLE_ISSUER_ID || "").trim();
    const classId = `${issuerId}.MembershipCard`;
    const accessToken = await getGoogleAccessToken();

    const body = {
      id: classId,
      issuerName: "Odivelas Sports Club",
      reviewStatus: "UNDER_REVIEW",
      hexBackgroundColor: "#000000", 
      cardTitle: {
        defaultValue: { language: "pt-PT", value: "ODIVELAS SPORTS CLUB" }
      },
      logo: {
        sourceUri: { uri: process.env.OSC_LOGO_URL },
        contentDescription: { defaultValue: { language: "pt-PT", value: "Logo OSC" } }
      },
      heroImage: {
        sourceUri: { uri: process.env.OSC_HERO_URL || process.env.OSC_FOOTER_LOGO_URL },
        contentDescription: { defaultValue: { language: "pt-PT", value: "Odivelas Sports Club" } }
      },
      classTemplateInfo: {
        cardRowTemplateInfos: [{
          threeItems: {
            startItem: { firstValue: { fieldPath: "object.textModulesData['memberNumber']" } },
            middleItem: { firstValue: { fieldPath: "object.textModulesData['type']" } },
            endItem: { firstValue: { fieldPath: "object.textModulesData['validUntil']" } }
          }
        }]
      },
      textModulesData: [
        { id: "memberNumber", header: "Nº Sócio" },
        { id: "type", header: "Tipo" },
        { id: "validUntil", header: "Válido até" }
      ]
    };

    const url = `https://walletobjects.googleapis.com/walletobjects/v1/genericClass/${encodeURIComponent(classId)}`;
    const r = await fetch(url, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    const txt = await r.text();
    if (!r.ok) return res.status(r.status).send(txt);
    return res.json({ ok: true, classId, updated: JSON.parse(txt) });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});

app.get("/admin/google-wallet/get-class", async (req, res) => {
  try {
    const token = (req.get("x-admin-token") || "").trim();
    if (!process.env.ADMIN_TOKEN || token !== String(process.env.ADMIN_TOKEN).trim()) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const issuerId = process.env.GOOGLE_ISSUER_ID;
    const classId = `${issuerId}.MembershipCard`;
    const accessToken = await getGoogleAccessToken();

    const r = await fetch(
      `https://walletobjects.googleapis.com/walletobjects/v1/genericClass/${encodeURIComponent(classId)}`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const txt = await r.text();
    return res.status(r.status).send(txt);
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`OSC Pass Service running on ${PORT}`));
