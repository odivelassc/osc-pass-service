const express = require("express");
const { v4: uuidv4 } = require("uuid");
const QRCode = require("qrcode");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
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

// ============ TOTP Security Functions ============

function base32Encode(buffer) {
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    
    while (bits >= 5) {
      output += base32Chars[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  
  if (bits > 0) {
    output += base32Chars[(value << (5 - bits)) & 31];
  }
  
  return output;
}

function generateTOTPSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function generateTOTP(secret, timeStep = 30, digits = 6) {
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const bytes = [];
  
  for (let i = 0; i < secret.length; i++) {
    const idx = base32Chars.indexOf(secret[i].toUpperCase());
    if (idx === -1) continue;
    
    value = (value << 5) | idx;
    bits += 5;
    
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  
  const key = Buffer.from(bytes);
  const time = Math.floor(Date.now() / 1000 / timeStep);
  const timeBuffer = Buffer.alloc(8);
  timeBuffer.writeBigUInt64BE(BigInt(time));
  
  const hmac = crypto.createHmac('sha1', key);
  hmac.update(timeBuffer);
  const hash = hmac.digest();
  
  const offset = hash[hash.length - 1] & 0xf;
  const code = (
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff)
  ) % Math.pow(10, digits);
  
  return String(code).padStart(digits, '0');
}

function verifyTOTP(secret, token, window = 1) {
  for (let i = -window; i <= window; i++) {
    const timeStep = Math.floor(Date.now() / 1000 / 30) + i;
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeBigUInt64BE(BigInt(timeStep));
    
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0;
    let value = 0;
    const bytes = [];
    
    for (let j = 0; j < secret.length; j++) {
      const idx = base32Chars.indexOf(secret[j].toUpperCase());
      if (idx === -1) continue;
      
      value = (value << 5) | idx;
      bits += 5;
      
      if (bits >= 8) {
        bytes.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }
    
    const key = Buffer.from(bytes);
    const hmac = crypto.createHmac('sha1', key);
    hmac.update(timeBuffer);
    const hash = hmac.digest();
    
    const offset = hash[hash.length - 1] & 0xf;
    const code = (
      ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff)
    ) % 1000000;
    
    if (String(code).padStart(6, '0') === token) {
      return true;
    }
  }
  
  return false;
}

// ============ End TOTP Functions ============


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

// ✅ FIX 1: Function signature restored
// ✅ FIX 2: logo field added to the object body
// ✅ FIX 3: Image URIs guarded — only included when valid https:// URLs
async function upsertGenericObject({ issuerId, classSuffix, objectSuffix, record }) {
  const accessToken = await getGoogleAccessToken();
  const classId = `${issuerId}.${classSuffix}`;
  const objectId = `${issuerId}.${objectSuffix}`;

  const url = `https://walletobjects.googleapis.com/walletobjects/v1/genericObject/${encodeURIComponent(objectId)}`;

  const logoUri = process.env.OSC_LOGO_URL;
  const heroUri = process.env.OSC_HERO_URL;
  const wideLogoUri = process.env.OSC_WIDE_LOGO_URL || logoUri; // Use dedicated wide logo or fall back to regular logo

  if (!logoUri || !logoUri.startsWith("https://")) {
    console.warn("⚠️  OSC_LOGO_URL is missing or not HTTPS — logo will not render on the card");
  }
  if (!wideLogoUri || !wideLogoUri.startsWith("https://")) {
    console.warn("⚠️  OSC_WIDE_LOGO_URL is missing or not HTTPS — wide logo will not render");
  }
  if (!heroUri || !heroUri.startsWith("https://")) {
    console.warn("⚠️  OSC_HERO_URL is missing or not HTTPS — hero image will not render on the card");
  }

  const body = {
    id: objectId,
    classId,
    state: record.status === "active" ? "ACTIVE" : "INACTIVE",
    genericType: "GENERIC_TYPE_UNSPECIFIED",
    // ✅ ALL visual fields belong on GenericObject for Generic passes
    cardTitle: { 
      defaultValue: { language: "pt-PT", value: "ODIVELAS SPORTS CLUB" } 
    },
    header: { 
      defaultValue: { language: "pt-PT", value: record.full_name } 
    },
    subheader: { 
      defaultValue: { language: "pt-PT", value: "Membro" } 
    },
    hexBackgroundColor: "#000000",
    barcode: {
      type: "QR_CODE",
      value: record.qr_validation_url,
      renderOptions: { appearance: "NON_CONFORMANT" }
    },
    // textModulesData with id fields that match the classTemplateInfo fieldPaths
    textModulesData: [
      { 
        id: "memberNumber", 
        header: "Nº", 
        body: String(record.member_number || "") 
      },
      { 
        id: "type", 
        header: "Tipo", 
        body: record.member_type || "Sócio" 
      },
      { 
        id: "validUntil", 
        header: "Válido até", 
        body: String(record.valid_until || "—") 
      }
    ],
    // Logo and hero image - only include if valid HTTPS URLs
    ...(logoUri?.startsWith("https://") && {
      logo: {
        sourceUri: { uri: logoUri },
        contentDescription: { 
          defaultValue: { language: "pt-PT", value: "OSC Logo" } 
        }
      }
    }),
    ...(wideLogoUri?.startsWith("https://") && {
      wideLogo: {
        sourceUri: { uri: wideLogoUri },
        contentDescription: { 
          defaultValue: { language: "pt-PT", value: "OSC Logo Wide" } 
        }
      }
    }),
    ...(heroUri?.startsWith("https://") && {
      heroImage: {
        sourceUri: { uri: heroUri },
        contentDescription: { 
          defaultValue: { language: "pt-PT", value: "OSC Banner" } 
        }
      }
    })
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

  // ✅ FIX: always return classId + objectId so the JWT URL is always generated,
  // even when the object already existed (409) or was just patched
  return { classId, objectId };
  // Note: 409 = already exists, which is fine — we still need the IDs for the JWT
}

function makeSaveToGoogleWalletUrl({ objectId, classId, origin }) {
  const saPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  // ✅ FIX: clear error if credentials path is missing or file doesn't exist
  if (!saPath) throw new Error("GOOGLE_APPLICATION_CREDENTIALS env var is not set");
  if (!fs.existsSync(saPath)) throw new Error(`Service account file not found at: ${saPath}`);
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

async function generateApplePass(record) {
  const crypto = require('crypto');
  const archiver = require('archiver');
  const { Readable } = require('stream');
  
  const certPath = process.env.APPLE_PASS_CERT_PATH;
  const keyPath = process.env.APPLE_PASS_KEY_PATH;
  const wwdrPath = process.env.APPLE_WWDR_CERT_PATH;
  const passTypeId = process.env.APPLE_PASS_TYPE_ID;
  const teamId = process.env.APPLE_TEAM_ID;

  if (!certPath || !keyPath || !wwdrPath || !passTypeId || !teamId) {
    throw new Error("Missing Apple Wallet configuration");
  }

  // Create pass.json manually
  const passJson = {
    formatVersion: 1,
    passTypeIdentifier: passTypeId,
    teamIdentifier: teamId,
    organizationName: "Odivelas Sports Club",
    serialNumber: record.token,
    description: "Cartão de Sócio",
    backgroundColor: "rgb(0, 0, 0)",
    foregroundColor: "rgb(255, 255, 255)",
    labelColor: "rgb(255, 255, 255)",
    logoText: "ODIVELAS SPORTS CLUB",
    storeCard: {
      headerFields: [{
        key: "member-status",
        label: "ESTADO",
        value: record.status === "active" ? "ATIVO" : "INATIVO"
      }],
      primaryFields: [{
        key: "member-name",
        label: "MEMBRO",
        value: record.full_name
      }],
      secondaryFields: [
        {
          key: "member-number",
          label: "Nº",
          value: String(record.member_number),
          textAlignment: "PKTextAlignmentLeft"
        },
        {
          key: "member-type",
          label: "Tipo",
          value: record.member_type || "Sócio",
          textAlignment: "PKTextAlignmentCenter"
        },
        {
          key: "valid-until",
          label: "Válido até",
          value: record.valid_until || "—",
          textAlignment: "PKTextAlignmentRight"
        }
      ],
      backFields: [
        {
          key: "full-name",
          label: "NOME COMPLETO",
          value: record.full_name
        },
        {
          key: "member-id",
          label: "ID DE MEMBRO",
          value: record.member_id
        },
        {
          key: "card-url",
          label: "CARTÃO DIGITAL",
          value: record.card_public_url
        },
        {
          key: "validation-url",
          label: "URL DE VALIDAÇÃO",
          value: record.qr_validation_url
        }
      ]
    },
    barcode: {
      format: "PKBarcodeFormatQR",
      message: record.qr_validation_url,
      messageEncoding: "iso-8859-1",
      altText: `Nº ${record.member_number}`
    }
  };

  const passJsonStr = JSON.stringify(passJson, null, 2);
  
  // Create manifest with SHA1 hashes
  const manifest = {
    "pass.json": crypto.createHash('sha1').update(passJsonStr).digest('hex')
  };

  // Add logo if available
  const logoPath = process.env.APPLE_PASS_LOGO_PATH;
  if (logoPath && fs.existsSync(logoPath)) {
    const logoData = fs.readFileSync(logoPath);
    manifest["logo.png"] = crypto.createHash('sha1').update(logoData).digest('hex');
    manifest["logo@2x.png"] = manifest["logo.png"];
    manifest["icon.png"] = manifest["logo.png"];
    manifest["icon@2x.png"] = manifest["logo.png"];
  }

  const manifestStr = JSON.stringify(manifest, null, 2);

  // Sign the manifest
  const certData = fs.readFileSync(certPath, 'utf8');
  const keyData = fs.readFileSync(keyPath, 'utf8');
  const wwdrData = fs.readFileSync(wwdrPath, 'utf8');

  const signer = crypto.createSign('sha1');
  signer.update(manifestStr);
  const signature = signer.sign(keyData);

  // Create the .pkpass zip
  return new Promise((resolve, reject) => {
    const archive = archiver('zip', { zlib: { level: 9 } });
    const chunks = [];
    
    archive.on('data', chunk => chunks.push(chunk));
    archive.on('end', () => resolve(Buffer.concat(chunks)));
    archive.on('error', reject);

    // Add files to archive
    archive.append(passJsonStr, { name: 'pass.json' });
    archive.append(manifestStr, { name: 'manifest.json' });
    archive.append(signature, { name: 'signature' });

    if (logoPath && fs.existsSync(logoPath)) {
      const logoData = fs.readFileSync(logoPath);
      archive.append(logoData, { name: 'logo.png' });
      archive.append(logoData, { name: 'logo@2x.png' });
      archive.append(logoData, { name: 'icon.png' });
      archive.append(logoData, { name: 'icon@2x.png' });
    }

    archive.finalize();
  });
}

app.post("/api/passes/issue", async (req, res) => {
  const { member_id, full_name, member_number, member_type, valid_until, status } = req.body || {};

  if (!member_id || !full_name || !member_number) {
    return res.status(400).json({
      error: "Missing required fields: member_id, full_name, member_number"
    });
  }

  // Check if member already exists - if so, update their data but keep TOTP secret
  let existingToken = null;
  let existingTotpSecret = null;
  for (const [token, rec] of store.entries()) {
    if (rec.member_id === member_id) {
      existingToken = token;
      existingTotpSecret = rec.totp_secret; // Preserve existing TOTP secret
      break;
    }
  }

  const token = existingToken || uuidv4().replaceAll("-", "");
  const totpSecret = existingTotpSecret || generateTOTPSecret(); // Generate new secret only for new members
  const baseUrl = process.env.PUBLIC_BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

  const payload = {
    token,
    member_id,
    full_name,
    member_number,
    member_type: member_type || "Sócio",
    valid_until: valid_until || null,
    status: status || "active",
    totp_secret: totpSecret, // Store TOTP secret
    card_public_url: `${baseUrl}/c/${token}`,
    qr_validation_url: `${baseUrl}/v/${token}`, // This will now generate dynamic codes
    apple_pkpass_url: null,
    google_wallet_url: null
  };

  store.set(token, payload);

  // ✅ FIX: surface the real reason google_wallet_url is null
  let googleWalletError = null;

  try {
    const issuerId = process.env.GOOGLE_ISSUER_ID;
    const origin = process.env.PUBLIC_BASE_URL || "https://osc-pass-service.onrender.com";
    const classSuffix = "MembershipCard";

    if (!issuerId) {
      googleWalletError = "GOOGLE_ISSUER_ID env var is not set";
      console.warn("⚠️  " + googleWalletError);
    } else if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
      googleWalletError = "GOOGLE_APPLICATION_CREDENTIALS env var is not set";
      console.warn("⚠️  " + googleWalletError);
    } else {
      const { classId, objectId } = await upsertGenericObject({
        issuerId,
        classSuffix,
        objectSuffix: payload.token,
        record: payload,
      });

      payload.google_wallet_url = makeSaveToGoogleWalletUrl({ objectId, classId, origin });
    }
  } catch (e) {
    googleWalletError = e.message || String(e);
    console.error("Google Wallet error:", e);
  }

  // Generate Apple Wallet pass URL
  if (process.env.APPLE_PASS_TYPE_ID && process.env.APPLE_TEAM_ID) {
    payload.apple_pkpass_url = `${baseUrl}/apple/${payload.token}.pkpass`;
  }

  // Include the error reason in the response so you can see it without checking logs
  res.json({
    ...payload,
    ...(googleWalletError && { google_wallet_error: googleWalletError })
  });
});

// ✅ FIX 4: Enhanced env-check with image URL validation
app.get("/admin/env-check", (req, res) => {
  const logoUrl  = process.env.OSC_LOGO_URL  || "";
  const heroUrl  = process.env.OSC_HERO_URL  || "";
  res.json({
    hasGoogleIssuerId:   !!process.env.GOOGLE_ISSUER_ID,
    hasCredentials:      !!process.env.GOOGLE_APPLICATION_CREDENTIALS,
    hasAdminToken:       !!process.env.ADMIN_TOKEN,
    hasLogoUrl:          !!logoUrl,
    logoUrlIsHttps:      logoUrl.startsWith("https://"),
    hasHeroUrl:          !!heroUrl,
    heroUrlIsHttps:      heroUrl.startsWith("https://"),
    hasPublicBaseUrl:    !!process.env.PUBLIC_BASE_URL,
  });
});

app.get("/v/:token", (req, res) => {
  const record = store.get(req.params.token);
  const totpCode = req.query.code; // Get TOTP code from query parameter

  let state = computeValidationState(record);
  let isValid = state.state === "VALID";
  
  // If TOTP code is provided, verify it
  if (totpCode && record && record.totp_secret) {
    const totpValid = verifyTOTP(record.totp_secret, totpCode);
    if (!totpValid) {
      state = { state: "INVALID_TOTP", label: "Código expirado" };
      isValid = false;
    }
  } else if (!totpCode && record) {
    // No TOTP code provided but record exists - show warning
    state = { state: "NO_CODE", label: "Código necessário" };
    isValid = false;
  }

  const title = isValid ? "VÁLIDO" : "NÃO VÁLIDO";
  const subtitle =
    state.state === "VALID"        ? "Cartão ativo" :
    state.state === "INVALID_TOTP" ? "Código de segurança expirado" :
    state.state === "NO_CODE"      ? "Escaneie o QR code do cartão" :
    state.state === "INACTIVE"     ? "Cartão desativado" :
    state.state === "EXPIRED"      ? "Cartão expirado" :
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
        ${logoUrl ? `<img class="brandLogo" src="${escapeHtml(logoUrl)}" alt="Odivelas Sports Club" />` : ""}
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
  res.send(state.state);
});

app.get("/c/:token", async (req, res) => {
  const record = store.get(req.params.token);
  if (!record) return res.status(404).send("Card not found");

  // Generate current TOTP code
  const currentTOTP = record.totp_secret ? generateTOTP(record.totp_secret) : '';
  
  // Create validation URL with TOTP code
  const validationUrlWithTOTP = `${record.qr_validation_url}?code=${currentTOTP}`;
  
  // Generate QR code with TOTP
  const qrDataUrl = await QRCode.toDataURL(validationUrlWithTOTP);
  const logoUrl = process.env.OSC_LOGO_URL || "";

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`
<!DOCTYPE html>
<html lang="pt">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cartão de Sócio - Odivelas Sports Club</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
      background: #000;
      color: #fff;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px 20px;
    }
    
    .logo {
      width: 120px;
      height: auto;
      margin-bottom: 40px;
    }
    
    .member-name {
      font-size: 32px;
      font-weight: 700;
      text-align: center;
      margin-bottom: 12px;
      letter-spacing: 0.5px;
    }
    
    .member-subtitle {
      color: #999;
      font-size: 16px;
      text-align: center;
      margin-bottom: 40px;
    }
    
    .wallet-buttons {
      display: flex;
      gap: 16px;
      justify-content: center;
      margin-bottom: 50px;
      flex-wrap: wrap;
    }
    
    .wallet-buttons a {
      display: block;
    }
    
    .wallet-buttons img {
      height: 50px;
      width: auto;
      transition: transform 0.2s;
    }
    
    .wallet-buttons img:hover {
      transform: scale(1.05);
    }
    
    .member-details {
      background: #1a1a1a;
      border-radius: 16px;
      padding: 24px;
      max-width: 400px;
      width: 100%;
      margin-bottom: 30px;
    }
    
    .detail-row {
      display: flex;
      justify-content: space-between;
      padding: 12px 0;
      border-bottom: 1px solid #333;
    }
    
    .detail-row:last-child {
      border-bottom: none;
    }
    
    .detail-label {
      color: #999;
      font-size: 14px;
    }
    
    .detail-value {
      font-weight: 600;
      font-size: 14px;
    }
    
    .qr-section {
      text-align: center;
    }
    
    .qr-section img {
      width: 200px;
      height: 200px;
      border-radius: 12px;
    }
    
    .footer-note {
      color: #666;
      font-size: 13px;
      text-align: center;
      margin-top: 30px;
      max-width: 400px;
    }
  </style>
</head>
<body>
  ${logoUrl ? `<img class="logo" src="${escapeHtml(logoUrl)}" alt="Odivelas Sports Club" />` : ''}
  
  <h1 class="member-name">${escapeHtml(record.full_name)}</h1>
  <p class="member-subtitle">Cartão de Sócio</p>
  
  <div class="wallet-buttons">
    ${record.google_wallet_url ? `
      <a href="${escapeHtml(record.google_wallet_url)}">
        <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/b/bb/Add_to_Google_Wallet_badge.svg/1280px-Add_to_Google_Wallet_badge.svg.png" alt="Add to Google Wallet" />
      </a>
    ` : ''}
    
    ${record.apple_pkpass_url ? `
      <a href="${escapeHtml(record.apple_pkpass_url)}">
        <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/3/30/Add_to_Apple_Wallet_badge.svg/1280px-Add_to_Apple_Wallet_badge.svg.png" alt="Add to Apple Wallet" />
      </a>
    ` : ''}
  </div>
  
  <div class="member-details">
    <div class="detail-row">
      <span class="detail-label">Nº Sócio</span>
      <span class="detail-value">${escapeHtml(record.member_number)}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Tipo</span>
      <span class="detail-value">${escapeHtml(record.member_type || "Sócio")}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Válido até</span>
      <span class="detail-value">${record.valid_until ? escapeHtml(record.valid_until) : "—"}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Estado</span>
      <span class="detail-value">${escapeHtml(String(record.status).toUpperCase())}</span>
    </div>
  </div>
  
  <div class="qr-section">
    <img id="qrCode" src="${qrDataUrl}" alt="QR Code de Validação" />
    <p style="color: #999; font-size: 12px; margin-top: 8px;">
      Código renova a cada 30 segundos
    </p>
  </div>
  
  <p class="footer-note">
    Adicione este cartão à sua carteira digital para acesso rápido e validação em eventos do clube.
  </p>
  
  <script>
    // Auto-refresh QR code every 30 seconds with new TOTP
    setInterval(async () => {
      try {
        const response = await fetch('/c/${record.token}/qr');
        const data = await response.json();
        document.getElementById('qrCode').src = data.qrDataUrl;
      } catch (error) {
        console.error('Failed to refresh QR code:', error);
      }
    }, 30000); // 30 seconds
  </script>
</body>
</html>
  `);
});

app.get("/c/:token/qr", async (req, res) => {
  const record = store.get(req.params.token);
  if (!record) return res.status(404).json({ error: "Card not found" });

  // Generate current TOTP code
  const currentTOTP = record.totp_secret ? generateTOTP(record.totp_secret) : '';
  
  // Create validation URL with TOTP code
  const validationUrlWithTOTP = `${record.qr_validation_url}?code=${currentTOTP}`;
  
  // Generate QR code
  const qrDataUrl = await QRCode.toDataURL(validationUrlWithTOTP);
  
  res.json({ qrDataUrl, expiresIn: 30 });
});

app.get("/apple/:token.pkpass", async (req, res) => {
  try {
    const record = store.get(req.params.token);
    if (!record) return res.status(404).send("Pass not found");

    const pkpassBuffer = await generateApplePass(record);
    
    res.setHeader("Content-Type", "application/vnd.apple.pkpass");
    res.setHeader("Content-Disposition", `attachment; filename="OSC_Member_${record.member_number}.pkpass"`);
    res.send(pkpassBuffer);
  } catch (error) {
    console.error("Apple Pass generation error:", error);
    res.status(500).json({ error: error.message });
  }
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
    const logoUri = process.env.OSC_LOGO_URL;
    const heroUri = process.env.OSC_HERO_URL;

    console.log("🔍 DEBUG - logoUri:", logoUri);
    console.log("🔍 DEBUG - heroUri:", heroUri);
    console.log("🔍 DEBUG - logoUri valid?", logoUri?.startsWith("https://"));
    console.log("🔍 DEBUG - heroUri valid?", heroUri?.startsWith("https://"));

    if (!logoUri || !logoUri.startsWith("https://")) {
      console.warn("⚠️  OSC_LOGO_URL is missing or not HTTPS — logo will not render");
    }
    if (!heroUri || !heroUri.startsWith("https://")) {
      console.warn("⚠️  OSC_HERO_URL is missing or not HTTPS — hero image will not render");
    }

    const body = {
      id: classId,
      issuerName: "Odivelas Sports Club",
      // GenericClass only supports layout template and shared data - NO visual fields
      classTemplateInfo: {
        cardTemplateOverride: {
          cardRowTemplateInfos: [{
            threeItems: {
              startItem:  { firstValue: { fields: [{ fieldPath: "object.textModulesData['memberNumber']" }] } },
              middleItem: { firstValue: { fields: [{ fieldPath: "object.textModulesData['type']" }] } },
              endItem:    { firstValue: { fields: [{ fieldPath: "object.textModulesData['validUntil']" }] } }
            }
          }]
        }
      },
      // Define the field metadata (headers only) at class level
      textModulesData: [
        { id: "memberNumber", header: "Nº" },
        { id: "type",         header: "Tipo" },
        { id: "validUntil",   header: "Válido até" }
      ]
    };

    console.log("🔍 DEBUG - Full body being sent to Google:");
    console.log(JSON.stringify(body, null, 2));

    const url = `https://walletobjects.googleapis.com/walletobjects/v1/genericClass/${encodeURIComponent(classId)}`;

    // Try POST first to force full class creation with all fields
    let r = await fetch("https://walletobjects.googleapis.com/walletobjects/v1/genericClass", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      // Try without reviewStatus - let Google default it to DRAFT
      body: JSON.stringify(body),
    });

    // If class already exists (409), try PATCH
    if (r.status === 409) {
      console.log("⚠️  Class already exists, trying PATCH...");
      r = await fetch(url, {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      });
    }

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

app.delete("/admin/google-wallet/delete-class", async (req, res) => {
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
      { 
        method: "DELETE",
        headers: { Authorization: `Bearer ${accessToken}` } 
      }
    );

    const txt = await r.text();
    if (!r.ok) {
      return res.status(r.status).json({ error: txt });
    }
    return res.json({ ok: true, deleted: classId, response: txt });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`OSC Pass Service running on ${PORT}`));
