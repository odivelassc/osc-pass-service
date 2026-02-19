const express = require("express");
const { v4: uuidv4 } = require("uuid");
const QRCode = require("qrcode");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { GoogleAuth } = require("google-auth-library");
const { fetch } = require("undici");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Database connection failed:', err);
  } else {
    console.log('✅ Database connected at:', res.rows[0].now);
  }
});

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[m]));
}

// ============ TOTP Security Functions (HEX-based, 10-second intervals, 8 digits) ============

function generateTOTP(hexSecret, timeStep = 10, digits = 8) {
  const key = Buffer.from(hexSecret, 'hex');
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

function verifyTOTP(hexSecret, token, window = 1) {
  const timeStep = 10; // 10 seconds
  const digits = 8;
  
  for (let i = -window; i <= window; i++) {
    const time = Math.floor(Date.now() / 1000 / timeStep) + i;
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeBigUInt64BE(BigInt(time));
    
    const key = Buffer.from(hexSecret, 'hex');
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
    
    if (String(code).padStart(digits, '0') === token) {
      return true;
    }
  }
  
  return false;
}

// ============ End TOTP Functions ============

function computeValidationState(record) {
  if (!record) return { state: "INVALID", label: "Inválido" };
  if (record.status !== "active") return { state: "INACTIVE", label: "Inativo" };
  if (record.valid_until) {
    const validUntil = new Date(record.valid_until);
    if (validUntil < new Date()) return { state: "EXPIRED", label: "Expirado" };
  }
  return { state: "VALID", label: "Válido" };
}

// Database helper functions
async function savePass(passData) {
  const query = `
    INSERT INTO passes (
      token, member_id, full_name, member_number, member_type,
      valid_until, status, totp_secret, card_public_url,
      qr_validation_url, apple_pkpass_url, google_wallet_url
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    ON CONFLICT (token) DO UPDATE SET
      full_name = EXCLUDED.full_name,
      member_number = EXCLUDED.member_number,
      member_type = EXCLUDED.member_type,
      valid_until = EXCLUDED.valid_until,
      status = EXCLUDED.status,
      apple_pkpass_url = EXCLUDED.apple_pkpass_url,
      google_wallet_url = EXCLUDED.google_wallet_url,
      updated_at = CURRENT_TIMESTAMP
    RETURNING *
  `;
  
  const values = [
    passData.token,
    passData.member_id,
    passData.full_name,
    passData.member_number,
    passData.member_type,
    passData.valid_until,
    passData.status,
    passData.totp_secret,
    passData.card_public_url,
    passData.qr_validation_url,
    passData.apple_pkpass_url,
    passData.google_wallet_url
  ];
  
  const result = await pool.query(query, values);
  return result.rows[0];
}

async function getPass(token) {
  const result = await pool.query('SELECT * FROM passes WHERE token = $1', [token]);
  return result.rows[0] || null;
}

async function findPassByMemberId(memberId) {
  const result = await pool.query('SELECT * FROM passes WHERE member_id = $1', [memberId]);
  return result.rows[0] || null;
}

async function getGoogleAccessToken() {
  const auth = new GoogleAuth({
    scopes: ["https://www.googleapis.com/auth/wallet_object.issuer"],
  });
  const client = await auth.getClient();
  const t = await client.getAccessToken();
  return t.token;
}

// Generate HEX secret from member_id (matching previous implementation)
function generateHexSecret(memberId) {
  const salt = process.env.TOTP_SALT || "osc-default-salt-2025";
  const hmac = crypto.createHmac('sha1', salt);
  hmac.update(memberId);
  const hash = hmac.digest('hex');
  return hash.substring(0, 40); // 20 bytes = 40 hex chars
}

async function upsertGenericObject({ issuerId, classSuffix, objectSuffix, record }) {
  const accessToken = await getGoogleAccessToken();

  const classId = `${issuerId}.${classSuffix}`;
  const objectId = `${issuerId}.${objectSuffix}`;

  const classUrl = `https://walletobjects.googleapis.com/walletobjects/v1/genericClass/${classId}`;
  const classRes = await fetch(classUrl, {
    method: "GET",
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!classRes.ok && classRes.status !== 404) {
    throw new Error(`Failed to check class existence: ${await classRes.text()}`);
  }

  if (classRes.status === 404) {
    const createClassRes = await fetch(
      "https://walletobjects.googleapis.com/walletobjects/v1/genericClass",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          id: classId,
          classTemplateInfo: {
            cardTemplateOverride: {
              cardRowTemplateInfos: [
                {
                  threeItems: {
                    startItem: {
                      firstValue: {
                        fields: [{ fieldPath: "object.textModulesData['number']" }]
                      }
                    },
                    middleItem: {
                      firstValue: {
                        fields: [{ fieldPath: "object.textModulesData['type']" }]
                      }
                    },
                    endItem: {
                      firstValue: {
                        fields: [{ fieldPath: "object.textModulesData['valid_until']" }]
                      }
                    }
                  }
                }
              ]
            }
          }
        }),
      }
    );

    if (!createClassRes.ok) {
      throw new Error(`Failed to create class: ${await createClassRes.text()}`);
    }
  }

  const objectUrl = `https://walletobjects.googleapis.com/walletobjects/v1/genericObject/${objectId}`;
  const checkRes = await fetch(objectUrl, {
    method: "GET",
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const existingData = checkRes.ok ? await checkRes.json() : null;

  // Generate HEX secret for this member
  const hexSecret = generateHexSecret(record.member_id);
  const baseUrl = process.env.PUBLIC_BASE_URL || "https://card.odivelassc.pt";
  
  // Convert HEX secret to Base64 for Google Wallet API
  const hexBuffer = Buffer.from(hexSecret, 'hex');
  const base64Secret = hexBuffer.toString('base64');

  const objectPayload = {
    id: objectId,
    classId,
    state: record.status === "active" ? "ACTIVE" : "INACTIVE",
    genericType: "GENERIC_OTHER",
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
    rotatingBarcode: {
      type: "QR_CODE",
      valuePattern: `${baseUrl}/v/${record.token}?code={totp_value_0}`,
      alternateText: " ",
      totpDetails: {
        periodMillis: 10000,
        algorithm: "TOTP_SHA1",
        parameters: [
          {
            key: base64Secret,
            valueLength: 8
          }
        ]
      }
    },
    logo: {
      sourceUri: {
        uri: process.env.OSC_LOGO_URL || "https://github.com/odivelassc/osc-pass-service/blob/main/logo_large.png?raw=true",
      },
      contentDescription: {
        defaultValue: { language: "pt-PT", value: "Odivelas Sports Club" },
      },
    },
    wideLogoImage: {
      sourceUri: {
        uri: process.env.OSC_WIDE_LOGO_URL || "https://github.com/odivelassc/osc-pass-service/blob/main/wide_logo_banner.png?raw=true",
      },
      contentDescription: {
        defaultValue: { language: "pt-PT", value: "Odivelas Sports Club Banner" },
      },
    },
    heroImage: {
      sourceUri: {
        uri: process.env.OSC_HERO_URL || "https://github.com/odivelassc/osc-pass-service/blob/main/osc%20logo.png?raw=true",
      },
      contentDescription: {
        defaultValue: { language: "pt-PT", value: "OSC Hero" },
      },
    },
    textModulesData: [
      {
        id: "number",
        header: "Nº",
        body: String(record.member_number),
      },
      {
        id: "type",
        header: "Tipo",
        body: record.member_type || "SÓCIO",
      },
      {
        id: "valid_until",
        header: "Válido até",
        body: record.valid_until || "—",
      },
    ],
  };

  if (existingData && existingData.version) {
    objectPayload.version = String(parseInt(existingData.version || "0", 10) + 1);
  }

  const method = existingData ? "PUT" : "POST";
  const url = existingData
    ? objectUrl
    : "https://walletobjects.googleapis.com/walletobjects/v1/genericObject";

  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(objectPayload),
  });

  if (!res.ok) {
    throw new Error(`Failed to upsert object: ${await res.text()}`);
  }

  return { classId, objectId };
}

function makeSaveToGoogleWalletUrl({ objectId, classId, origin }) {
  const claims = {
    iss: process.env.GOOGLE_APPLICATION_CREDENTIALS ? 
      JSON.parse(fs.readFileSync(process.env.GOOGLE_APPLICATION_CREDENTIALS, "utf8")).client_email : 
      "service-account@project.iam.gserviceaccount.com",
    aud: "google",
    origins: [origin],
    typ: "savetowallet",
    payload: {
      genericObjects: [{ id: objectId, classId }],
    },
  };

  const privateKey = process.env.GOOGLE_APPLICATION_CREDENTIALS ?
    JSON.parse(fs.readFileSync(process.env.GOOGLE_APPLICATION_CREDENTIALS, "utf8")).private_key :
    "";

  const token = jwt.sign(claims, privateKey, { algorithm: "RS256" });
  return `https://pay.google.com/gp/v/save/${token}`;
}

async function generateApplePass(record) {
  const { execSync } = require('child_process');
  const archiver = require('archiver');
  
  const certPath = process.env.APPLE_PASS_CERT_PATH;
  const keyPath = process.env.APPLE_PASS_KEY_PATH;
  const wwdrPath = process.env.APPLE_WWDR_CERT_PATH;
  const passTypeId = process.env.APPLE_PASS_TYPE_ID;
  const teamId = process.env.APPLE_TEAM_ID;

  if (!certPath || !keyPath || !wwdrPath || !passTypeId || !teamId) {
    throw new Error("Missing Apple Wallet configuration");
  }

  const tempDir = `/tmp/pass-${record.token}-${Date.now()}`;
  
  try {
    execSync(`mkdir -p ${tempDir}`);

    const passJson = {
      formatVersion: 1,
      passTypeIdentifier: passTypeId,
      teamIdentifier: teamId,
      organizationName: "Odivelas Sports Club",
      serialNumber: record.token,
      description: "Odivelas Sports Club - Membership Card",
      logoText: "Odivelas Sports Club",
      backgroundColor: "#000000",
      labelColor: "#fae442",
      foregroundColor: "#ffffff",
      storeCard: {
        headerFields: [{
          key: "number",
          label: "Number",
          value: String(record.member_number)
        }],
        secondaryFields: [
          {
            key: "member",
            label: "Member",
            value: record.full_name
          },
          {
            key: "card-type",
            label: "Type",
            value: record.member_type || "Sócio"
          },
          {
            key: "valid-until",
            label: "Valid until",
            value: record.valid_until || "—"
          }
        ]
      },
      barcode: {
        format: "PKBarcodeFormatQR",
        message: record.qr_validation_url,
        messageEncoding: "iso-8859-1"
      }
    };

    const passJsonStr = JSON.stringify(passJson);
    fs.writeFileSync(`${tempDir}/pass.json`, passJsonStr);

    const manifest = {
      "pass.json": crypto.createHash('sha1').update(passJsonStr).digest('hex')
    };

    const logoPath = process.env.APPLE_PASS_LOGO_PATH || process.env.APPLE_PASS_ICON_PATH;
    const stripPath = process.env.APPLE_PASS_STRIP_PATH;
    
    const oscLogoPath = logoPath || stripPath;
    
    if (oscLogoPath && fs.existsSync(oscLogoPath)) {
      const logoData = fs.readFileSync(oscLogoPath);
      
      fs.writeFileSync(`${tempDir}/icon.png`, logoData);
      fs.writeFileSync(`${tempDir}/icon@2x.png`, logoData);
      manifest["icon.png"] = crypto.createHash('sha1').update(logoData).digest('hex');
      manifest["icon@2x.png"] = manifest["icon.png"];
      
      fs.writeFileSync(`${tempDir}/strip.png`, logoData);
      fs.writeFileSync(`${tempDir}/strip@2x.png`, logoData);
      manifest["strip.png"] = crypto.createHash('sha1').update(logoData).digest('hex');
      manifest["strip@2x.png"] = manifest["strip.png"];
    }

    const manifestStr = JSON.stringify(manifest);
    fs.writeFileSync(`${tempDir}/manifest.json`, manifestStr);

    execSync(`openssl smime -binary -sign \\
      -certfile "${wwdrPath}" \\
      -signer "${certPath}" \\
      -inkey "${keyPath}" \\
      -in "${tempDir}/manifest.json" \\
      -out "${tempDir}/signature" \\
      -outform DER`);

    return new Promise((resolve, reject) => {
      const archive = archiver('zip', { zlib: { level: 9 } });
      const chunks = [];
      
      archive.on('data', chunk => chunks.push(chunk));
      archive.on('end', () => {
        execSync(`rm -rf ${tempDir}`);
        resolve(Buffer.concat(chunks));
      });
      archive.on('error', (err) => {
        execSync(`rm -rf ${tempDir}`);
        reject(err);
      });

      archive.file(`${tempDir}/pass.json`, { name: 'pass.json' });
      archive.file(`${tempDir}/manifest.json`, { name: 'manifest.json' });
      archive.file(`${tempDir}/signature`, { name: 'signature' });
      
      if (fs.existsSync(`${tempDir}/icon.png`)) {
        archive.file(`${tempDir}/icon.png`, { name: 'icon.png' });
        archive.file(`${tempDir}/icon@2x.png`, { name: 'icon@2x.png' });
      }
      
      if (fs.existsSync(`${tempDir}/strip.png`)) {
        archive.file(`${tempDir}/strip.png`, { name: 'strip.png' });
        archive.file(`${tempDir}/strip@2x.png`, { name: 'strip@2x.png' });
      }

      archive.finalize();
    });
  } catch (error) {
    try {
      execSync(`rm -rf ${tempDir}`);
    } catch (e) {
      // Ignore cleanup errors
    }
    throw error;
  }
}

app.delete("/api/passes/:member_id", async (req, res) => {
  try {
    const { member_id } = req.params;
    
    // Find the pass by member_id
    const pass = await findPassByMemberId(member_id);
    
    if (!pass) {
      return res.status(404).json({ error: "Pass not found" });
    }
    
    // Delete from database
    await pool.query('DELETE FROM passes WHERE member_id = $1', [member_id]);
    
    res.json({ 
      success: true, 
      message: "Pass deleted successfully",
      deleted_token: pass.token 
    });
  } catch (error) {
    console.error('Error deleting pass:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/passes/issue", async (req, res) => {
  const { member_id, full_name, member_number, member_type, valid_until, status } = req.body || {};

  if (!member_id || !full_name || !member_number) {
    return res.status(400).json({
      error: "Missing required fields: member_id, full_name, member_number"
    });
  }

  try {
    const existingPass = await findPassByMemberId(member_id);
    
    const token = existingPass ? existingPass.token : uuidv4().replaceAll("-", "");
    const totpSecret = existingPass ? existingPass.totp_secret : generateHexSecret(member_id);
    const baseUrl = process.env.PUBLIC_BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

    const payload = {
      token,
      member_id,
      full_name,
      member_number,
      member_type: member_type || "SÓCIO",
      valid_until: valid_until || null,
      status: status || "active",
      totp_secret: totpSecret,
      card_public_url: `${baseUrl}/c/${token}`,
      qr_validation_url: `${baseUrl}/v/${token}`,
      apple_pkpass_url: null,
      google_wallet_url: null
    };

    await savePass(payload);

    let googleWalletError = null;

    try {
      const issuerId = process.env.GOOGLE_ISSUER_ID;
      const origin = process.env.PUBLIC_BASE_URL || "https://osc-pass-service.onrender.com";
      const classSuffix = "MembershipCardV2";

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

    if (process.env.APPLE_PASS_TYPE_ID && process.env.APPLE_TEAM_ID) {
      payload.apple_pkpass_url = `${baseUrl}/apple/${payload.token}.pkpass`;
    }

    await savePass(payload);

    res.json({
      ...payload,
      ...(googleWalletError && { google_wallet_error: googleWalletError })
    });
  } catch (error) {
    console.error('Error issuing pass:', error);
    res.status(500).json({ error: error.message });
  }
});

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

app.get("/v/:token", async (req, res) => {
  const record = await getPass(req.params.token);
  const totpCode = req.query.code;

  let state = computeValidationState(record);
  let isValid = state.state === "VALID";
  
  if (totpCode && record && record.totp_secret) {
    const totpValid = verifyTOTP(record.totp_secret, totpCode);
    if (!totpValid) {
      state = { state: "INVALID_TOTP", label: "Código expirado" };
      isValid = false;
    }
  } else if (!totpCode && record) {
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
<!DOCTYPE html>
<html lang="pt">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} | ${clubName}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #000;
      --yellow: #F4C400;
      --red: #FF3B30;
      --white: #FFFFFF;
      --muted: rgba(255,255,255,.65);
      --ring: rgba(255,255,255,.12);
    }
    body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--white);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
    .wrap{max-width:600px;width:100%}
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

      ${record && record.full_name ? `<div class="hint">Sócio: ${escapeHtml(record.full_name)}</div>` : ""}
    </div>
  </div>
</body>
</html>
  `);
});

app.get("/v/:token.txt", async (req, res) => {
  const record = await getPass(req.params.token);
  const state = computeValidationState(record);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.send(state.state);
});

app.get("/c/:token", async (req, res) => {
  const record = await getPass(req.params.token);
  if (!record) return res.status(404).send("Card not found");

  const currentTOTP = record.totp_secret ? generateTOTP(record.totp_secret) : '';
  
  const validationUrlWithTOTP = `${record.qr_validation_url}?code=${currentTOTP}`;
  
  const qrDataUrl = await QRCode.toDataURL(validationUrlWithTOTP);
  const logoUrl = process.env.OSC_LOGO_URL || "";

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`
<!DOCTYPE html>
<html lang="pt">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cartão de Sócio - ${escapeHtml(record.full_name)}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #000;
      color: #fff;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    
    .logo {
      max-width: 150px;
      height: auto;
      margin-bottom: 30px;
    }
    
    .member-name {
      font-size: 32px;
      font-weight: 700;
      text-align: center;
      margin-bottom: 8px;
    }
    
    .member-subtitle {
      font-size: 16px;
      color: #999;
      text-align: center;
      margin-bottom: 30px;
    }
    
    .wallet-buttons {
      display: flex;
      gap: 16px;
      justify-content: center;
      margin-bottom: 40px;
      flex-wrap: wrap;
    }
    
    .wallet-buttons a {
      display: block;
      transition: opacity 0.2s;
    }
    
    .wallet-buttons a:hover {
      opacity: 0.8;
    }
    
    .wallet-buttons img {
      height: 50px;
      width: auto;
    }
    
    .member-details {
      background: #1a1a1a;
      border-radius: 12px;
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
      <span class="detail-value">${escapeHtml(record.member_type || 'Sócio')}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Válido até</span>
      <span class="detail-value">${escapeHtml(record.valid_until || '—')}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Estado</span>
      <span class="detail-value">${record.status === 'active' ? 'ATIVO' : 'INATIVO'}</span>
    </div>
  </div>
  
  <div class="qr-section">
    <img id="qrCode" src="${qrDataUrl}" alt="QR Code de Validação" />
    <p style="color: #999; font-size: 12px; margin-top: 8px;">
      Código renova a cada 10 segundos
    </p>
  </div>
  
  <p class="footer-note">
    Adicione este cartão à sua carteira digital para acesso rápido e validação em eventos do clube.
  </p>
  
  <script>
    setInterval(async () => {
      try {
        const response = await fetch('/c/${record.token}/qr');
        const data = await response.json();
        document.getElementById('qrCode').src = data.qrDataUrl;
      } catch (error) {
        console.error('Failed to refresh QR code:', error);
      }
    }, 10000); // Refresh every 10 seconds
  </script>
</body>
</html>
  `);
});

app.get("/c/:token/qr", async (req, res) => {
  const record = await getPass(req.params.token);
  if (!record) return res.status(404).json({ error: "Card not found" });

  const currentTOTP = record.totp_secret ? generateTOTP(record.totp_secret) : '';
  
  const validationUrlWithTOTP = `${record.qr_validation_url}?code=${currentTOTP}`;
  
  const qrDataUrl = await QRCode.toDataURL(validationUrlWithTOTP);
  
  res.json({ qrDataUrl, expiresIn: 10 });
});

app.get("/apple/:token.pkpass", async (req, res) => {
  try {
    const record = await getPass(req.params.token);
    if (!record) return res.status(404).send("Pass not found");

    const pkpassBuffer = await generateApplePass(record);
    
    res.setHeader("Content-Type", "application/vnd.apple.pkpass");
    res.setHeader("Content-Disposition", `inline; filename="OSC_Member_${record.member_number}.pkpass"`);
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

app.get("/admin/debug-apple-logo", (req, res) => {
  const logoPath = process.env.APPLE_PASS_LOGO_PATH;
  const iconPath = process.env.APPLE_PASS_ICON_PATH;
  const stripPath = process.env.APPLE_PASS_STRIP_PATH;
  
  const result = {
    env: {
      logoPath,
      iconPath,
      stripPath
    },
    exists: {
      logo: logoPath ? fs.existsSync(logoPath) : false,
      icon: iconPath ? fs.existsSync(iconPath) : false,
      strip: stripPath ? fs.existsSync(stripPath) : false
    },
    filesInSrc: []
  };
  
  try {
    const allFiles = fs.readdirSync('/opt/render/project/src');
    result.filesInSrc = allFiles.filter(f => 
      f.toLowerCase().includes('logo') || 
      f.toLowerCase().includes('osc') ||
      f.endsWith('.png')
    );
  } catch (e) {
    result.error = e.message;
  }
  
  res.json(result);
});

app.post("/admin/google-wallet/brand-class", async (req, res) => {
  try {
    const token = (req.get("x-admin-token") || "").trim();
    const adminToken = String(process.env.ADMIN_TOKEN || "").trim();
    if (!adminToken || token !== adminToken) return res.status(401).json({ error: "Unauthorized" });

    const issuerId = String(process.env.GOOGLE_ISSUER_ID || "").trim();
    if (!issuerId) return res.status(400).json({ error: "GOOGLE_ISSUER_ID not set" });

    const classSuffix = req.body.classSuffix || "MembershipCardV2";
    const classId = `${issuerId}.${classSuffix}`;

    const accessToken = await getGoogleAccessToken();

    const classUrl = `https://walletobjects.googleapis.com/walletobjects/v1/genericClass/${classId}`;
    const checkRes = await fetch(classUrl, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    let existingVersion = 0;
    if (checkRes.ok) {
      const existing = await checkRes.json();
      existingVersion = parseInt(existing.version || "0", 10);
    }

    const payload = {
      id: classId,
      version: String(existingVersion + 1),
      classTemplateInfo: {
        cardTemplateOverride: {
          cardRowTemplateInfos: [
            { oneItem: { item: { firstValue: { fields: [{ fieldPath: "class.genericType" }] } } } },
            { twoItems: { startItem: { firstValue: { fields: [{ fieldPath: "object.subheader" }] } }, endItem: { firstValue: { fields: [{ fieldPath: "object.header" }] } } } }
          ]
        }
      }
    };

    const method = checkRes.ok ? "PUT" : "POST";
    const url = checkRes.ok
      ? classUrl
      : "https://walletobjects.googleapis.com/walletobjects/v1/genericClass";

    const res2 = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!res2.ok) {
      const text = await res2.text();
      return res.status(res2.status).json({ error: text });
    }

    const data = await res2.json();
    res.json({ message: `Class ${method === "PUT" ? "updated" : "created"}`, data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch("/admin/google-wallet/brand-class", async (req, res) => {
  try {
    const token = (req.get("x-admin-token") || "").trim();
    const adminToken = String(process.env.ADMIN_TOKEN || "").trim();
    if (!adminToken || token !== adminToken) return res.status(401).json({ error: "Unauthorized" });

    const issuerId = String(process.env.GOOGLE_ISSUER_ID || "").trim();
    if (!issuerId) return res.status(400).json({ error: "GOOGLE_ISSUER_ID not set" });

    const classSuffix = req.body.classSuffix || "MembershipCardV2";
    const classId = `${issuerId}.${classSuffix}`;

    const accessToken = await getGoogleAccessToken();

    const classUrl = `https://walletobjects.googleapis.com/walletobjects/v1/genericClass/${classId}`;
    const checkRes = await fetch(classUrl, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!checkRes.ok) {
      return res.status(404).json({ error: "Class not found" });
    }

    const existing = await checkRes.json();
    const currentVersion = parseInt(existing.version || "0", 10);

    const payload = {
      ...existing,
      version: String(currentVersion + 1),
      classTemplateInfo: {
        cardTemplateOverride: {
          cardRowTemplateInfos: [
            { oneItem: { item: { firstValue: { fields: [{ fieldPath: "class.genericType" }] } } } },
            { twoItems: { startItem: { firstValue: { fields: [{ fieldPath: "object.subheader" }] } }, endItem: { firstValue: { fields: [{ fieldPath: "object.header" }] } } } }
          ]
        }
      }
    };

    const res2 = await fetch(classUrl, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!res2.ok) {
      const text = await res2.text();
      return res.status(res2.status).json({ error: text });
    }

    const data = await res2.json();
    res.json({ message: "Class updated", data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/admin/google-wallet/delete-class", async (req, res) => {
  try {
    const token = (req.get("x-admin-token") || "").trim();
    const adminToken = String(process.env.ADMIN_TOKEN || "").trim();
    if (!adminToken || token !== adminToken) return res.status(401).json({ error: "Unauthorized" });

    const issuerId = String(process.env.GOOGLE_ISSUER_ID || "").trim();
    if (!issuerId) return res.status(400).json({ error: "GOOGLE_ISSUER_ID not set" });

    const classSuffix = req.query.classSuffix || "MembershipCardV2";
    const classId = `${issuerId}.${classSuffix}`;

    const accessToken = await getGoogleAccessToken();

    const res2 = await fetch(`https://walletobjects.googleapis.com/walletobjects/v1/genericClass/${classId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!res2.ok) {
      const text = await res2.text();
      return res.status(res2.status).json({ error: text });
    }

    res.json({ message: "Class deleted" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/admin/google-wallet/get-class", async (req, res) => {
  try {
    const token = (req.get("x-admin-token") || "").trim();
    const adminToken = String(process.env.ADMIN_TOKEN || "").trim();
    if (!adminToken || token !== adminToken) return res.status(401).json({ error: "Unauthorized" });

    const issuerId = String(process.env.GOOGLE_ISSUER_ID || "").trim();
    if (!issuerId) return res.status(400).json({ error: "GOOGLE_ISSUER_ID not set" });

    const classSuffix = req.query.classSuffix || "MembershipCardV2";
    const classId = `${issuerId}.${classSuffix}`;

    const accessToken = await getGoogleAccessToken();

    const res2 = await fetch(`https://walletobjects.googleapis.com/walletobjects/v1/genericClass/${classId}`, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!res2.ok) {
      return res.status(res2.status).json({ error: await res2.text() });
    }

    const data = await res2.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
