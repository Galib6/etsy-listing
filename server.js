require("dotenv").config();
const express = require("express");
const axios = require("axios");
const bodyParser = require("body-parser");
const qs = require("qs");
const fs = require("fs");
const path = require("path");

const {
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,
  BASE_URL = "http://localhost:3000",
  SHOP_ID,
  TOKEN_STORE = "./tokens.json",
  PORT = 3000,
} = process.env;

if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI || !SHOP_ID) {
  console.warn("Missing env variables. Fill .env from .env.example");
}

const app = express();
app.use(bodyParser.json());

/* ---------- Helper: token storage (simple file-based demo) ---------- */
const tokenFile = path.resolve(TOKEN_STORE);
function readTokens() {
  if (!fs.existsSync(tokenFile)) return {};
  try {
    return JSON.parse(fs.readFileSync(tokenFile, "utf8"));
  } catch (e) {
    return {};
  }
}
function saveTokens(obj) {
  fs.writeFileSync(tokenFile, JSON.stringify(obj, null, 2), "utf8");
}

/* ---------- 1) Login route: redirect to Etsy OAuth connect ---------- */
/* Authorization URL (Etsy): https://www.etsy.com/oauth/connect */
app.get("/auth/login", (req, res) => {
  const scopes = ["listings_w"].join(" ");
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: scopes,
    state: Math.random().toString(36).slice(2), // short state for CSRF protection (improve in prod)
  });
  const url = `https://www.etsy.com/oauth/connect?${params.toString()}`;
  return res.redirect(url);
});

/* ---------- 2) Callback: exchange code for tokens ---------- */
/* Token endpoint: https://openapi.etsy.com/v3/public/oauth/token */
app.get("/auth/callback", async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.status(400).send(`Auth error: ${error}`);

  if (!code) return res.status(400).send("Missing code parameter.");

  try {
    const tokenResp = await axios.post(
      "https://openapi.etsy.com/v3/public/oauth/token",
      qs.stringify({
        grant_type: "authorization_code",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        redirect_uri: REDIRECT_URI,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    // tokenResp.data contains access_token, refresh_token, expires_in, scope, etc.
    const tokens = tokenResp.data;
    // Save tokens to file (demo). In prod use a database and associate with user.
    saveTokens({ ...readTokens(), etsy: tokens });

    return res.json({
      message:
        "Tokens saved (demo). You can now call /listings with Authorization",
      tokens: { ...tokens, access_token: "***" }, // avoid leaking
    });
  } catch (err) {
    console.error(err.response ? err.response.data : err.message);
    return res.status(500).send("Token exchange failed. See server logs.");
  }
});

/* ---------- 3) Refresh token endpoint (optional) ---------- */
app.post("/token/refresh", async (req, res) => {
  const store = readTokens();
  const refresh_token = store?.etsy?.refresh_token;
  if (!refresh_token) return res.status(400).send("No refresh token stored.");

  try {
    const r = await axios.post(
      "https://openapi.etsy.com/v3/public/oauth/token",
      qs.stringify({
        grant_type: "refresh_token",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const tokens = r.data;
    saveTokens({ ...store, etsy: tokens });
    return res.json({
      message: "Refreshed",
      tokens: { ...tokens, access_token: "***" },
    });
  } catch (err) {
    console.error(err.response ? err.response.data : err.message);
    return res.status(500).send("Refresh failed.");
  }
});

/* ---------- 4) Create a draft listing ---------- */
/*
  Endpoint used: POST /v3/application/shops/{shop_id}/listings
  Requires:
    - Authorization: Bearer <access_token>
    - x-api-key: <your app API key (CLIENT_ID)>
  The createDraftListing endpoint accepts many fields. Minimal example below.
  Note: to make listing active you must attach images and/or call updateListing with state=active.
*/
app.post("/listings", async (req, res) => {
  const store = readTokens();
  const access_token = store?.etsy?.access_token;
  if (!access_token)
    return res.status(401).send("No access token. Login first via /auth/login");

  // Basic validation -- the body should include title, description, price, quantity, taxonomy_id, when_made, who_made
  const {
    title = "Sample Title from API",
    description = "Sample description",
    price = "10.00",
    quantity = 1,
    who_made = "i_made_it",
    when_made = "2020_2023",
    taxonomy_id = 1,
  } = req.body;

  try {
    const endpoint = `https://api.etsy.com/v3/application/shops/${SHOP_ID}/listings`;
    const response = await axios.post(
      endpoint,
      {
        title,
        description,
        price,
        quantity,
        who_made,
        when_made,
        taxonomy_id,
      },
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          "x-api-key": CLIENT_ID,
          "Content-Type": "application/json",
        },
      }
    );

    // Response includes created draft listing object
    return res.json({ ok: true, listing: response.data });
  } catch (err) {
    console.error(
      "Create listing error:",
      err.response ? err.response.data : err.message
    );
    const status = err.response?.status || 500;
    return res
      .status(status)
      .json({ error: err.response?.data || err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Etsy backend demo running on ${BASE_URL}:${PORT}`);
  console.log(`1) Visit ${BASE_URL}/auth/login to start OAuth2 flow.`);
});
