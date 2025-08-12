// server.js
require("dotenv").config();
const express = require("express");
const axios = require("axios");
const qs = require("qs");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const FormData = require("form-data");

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
  console.warn(
    "Warning: Make sure CLIENT_ID, CLIENT_SECRET, REDIRECT_URI and SHOP_ID are set in .env"
  );
}

const app = express();
app.use(bodyParser.json());

// simple file-based token store (demo only)
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

// PKCE helper functions
function base64URLEncode(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function generateCodeVerifier() {
  return base64URLEncode(crypto.randomBytes(32));
}
function generateCodeChallenge(verifier) {
  return base64URLEncode(crypto.createHash("sha256").update(verifier).digest());
}

// In-memory PKCE store for demo (state -> code_verifier). In prod use sessions/DB.
const pkceStore = {};

// ---------- Routes ----------

// 1) Start OAuth login (generate PKCE)
app.get("/auth/login", (req, res) => {
  const code_verifier = generateCodeVerifier();
  const code_challenge = generateCodeChallenge(code_verifier);
  const state = crypto.randomBytes(8).toString("hex");

  // store verifier by state
  pkceStore[state] = { code_verifier, createdAt: Date.now() };

  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: [
      "address_r",
      "address_w",
      "billing_r",
      "cart_r",
      "cart_w",
      "email_r",
      "favorites_r",
      "favorites_w",
      "feedback_r",
      "listings_d",
      "listings_r",
      "listings_w",
      "profile_r",
      "profile_w",
      "recommend_r",
      "recommend_w",
      "shops_r",
      "shops_w",
      "transactions_r",
      "transactions_w",
    ].join(" "), // request all available scopes
    state,
    code_challenge,
    code_challenge_method: "S256",
  });

  const url = `https://www.etsy.com/oauth/connect?${params.toString()}`;
  res.redirect(url);
});

// 2) Callback: exchange code + code_verifier for tokens
app.get("/auth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;
  if (error) {
    return res
      .status(400)
      .send(`Auth error: ${error} - ${error_description || ""}`);
  }
  if (!code || !state) return res.status(400).send("Missing code or state");

  const entry = pkceStore[state];
  if (!entry)
    return res
      .status(400)
      .send("Missing PKCE verifier for this state. Try logging in again.");

  const { code_verifier } = entry;
  // optional: clean old pkceStore entries
  delete pkceStore[state];

  try {
    const tokenResp = await axios.post(
      "https://openapi.etsy.com/v3/public/oauth/token",
      qs.stringify({
        grant_type: "authorization_code",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const tokens = tokenResp.data; // contains access_token, refresh_token, expires_in, scope, etc.
    // Save tokens associated to 'etsy' key (demo). In prod, associate with user account.
    const store = readTokens();
    store.etsy = tokens;
    saveTokens(store);

    // return a friendly JSON (avoid sending raw access token to browser in prod)
    return res.json({
      message: "OAuth success — tokens saved (demo).",
      scope: tokens.scope,
      expires_in: tokens.expires_in,
    });
  } catch (err) {
    console.error("Token exchange error:", err.response?.data || err.message);
    return res
      .status(500)
      .send("Token exchange failed. Check server logs for details.");
  }
});

// 3) Refresh token endpoint (use when access_token expired)
app.post("/token/refresh", async (req, res) => {
  const store = readTokens();
  const refresh_token = store?.etsy?.refresh_token;
  if (!refresh_token)
    return res.status(400).send("No refresh token stored. Re-authenticate.");

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
    store.etsy = tokens;
    saveTokens(store);

    return res.json({
      message: "Refreshed tokens saved",
      expires_in: tokens.expires_in,
    });
  } catch (err) {
    console.error("Refresh error:", err.response?.data || err.message);
    return res.status(500).send("Token refresh failed.");
  }
});

// Helper: get current access token (or 401)
function getAccessTokenOr401(res) {
  const store = readTokens();
  const access_token = store?.etsy?.access_token;
  if (!access_token) {
    res
      .status(401)
      .send("No access token available. Authenticate via /auth/login");
    return null;
  }
  return access_token;
}

// 4) Create a draft listing
app.post("/listings", async (req, res) => {
  const access_token = getAccessTokenOr401(res);
  if (!access_token) return;

  // Validate body minimally. Etsy requires several fields; adapt as needed.
  const {
    title = "API Created Listing",
    description = "Created via API",
    price = "10.00",
    quantity = 1,
    who_made = "i_made_it",
    when_made = "2020_2023",
    taxonomy_id = 1,
    shipping_profile_id,
  } = req.body || {};

  try {
    const endpoint = `https://api.etsy.com/v3/application/shops/${SHOP_ID}/listings`;
    const r = await axios.post(
      endpoint,
      {
        title,
        description,
        price,
        quantity,
        who_made,
        when_made,
        taxonomy_id,
        shipping_profile_id,
      },
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          "x-api-key": CLIENT_ID,
          "Content-Type": "application/json",
        },
      }
    );

    // return the created listing (draft)
    return res.json({ ok: true, listing: r.data });
  } catch (err) {
    console.error("Create listing error:", err.response?.data || err.message);
    const status = err.response?.status || 500;
    return res
      .status(status)
      .json({ error: err.response?.data || err.message });
  }
});

// 7) Simple endpoint to show token status (for debugging)
app.get("/tokens", (req, res) => {
  const store = readTokens();
  res.json(store);
});

// health
// Proxy Etsy API: Get authenticated user info
app.get("/me", async (req, res) => {
  const access_token = getAccessTokenOr401(res);
  if (!access_token) return;

  try {
    const endpoint = "https://openapi.etsy.com/v3/application/users/me";
    const r = await axios.get(endpoint, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        "x-api-key": CLIENT_ID,
        "Content-Type": "application/json",
      },
    });
    return res.json(r.data);
  } catch (err) {
    console.error("Get user info error:", err.response?.data || err.message);
    const status = err.response?.status || 500;
    return res
      .status(status)
      .json({ error: err.response?.data || err.message });
  }
});

// 8) Get listings by shop (proxy Etsy getListingsByShop API)
app.get("/shops/listings", async (req, res) => {
  const access_token = getAccessTokenOr401(res);
  if (!access_token) return;

  let { shop_id } = req.params;

  shop_id = SHOP_ID;

  // Supported query params
  const {
    state = "active",
    limit = 5,
    offset = 0,
    sort_on = "created",
    sort_order = "desc",
    includes,
    legacy,
  } = req.query;

  // Build query string
  const params = new URLSearchParams();
  if (state) params.append("state", state);
  if (limit) params.append("limit", limit);
  if (offset) params.append("offset", offset);
  if (sort_on) params.append("sort_on", sort_on);
  if (sort_order) params.append("sort_order", sort_order);
  if (includes) {
    // includes can be a comma-separated string or array
    if (Array.isArray(includes)) {
      includes.forEach((inc) => params.append("includes", inc));
    } else {
      String(includes)
        .split(",")
        .forEach((inc) => params.append("includes", inc.trim()));
    }
  }
  if (legacy !== undefined) params.append("legacy", legacy);

  const endpoint = `https://openapi.etsy.com/v3/application/shops/${shop_id}/listings?${params.toString()}`;
  try {
    const r = await axios.get(endpoint, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        "x-api-key": CLIENT_ID,
        "Content-Type": "application/json",
      },
    });
    return res.json(r.data);
  } catch (err) {
    console.error("Get listings error:", err.response?.data || err.message);
    const status = err.response?.status || 500;
    return res
      .status(status)
      .json({ error: err.response?.data || err.message });
  }
});

// Etsy Seller Taxonomy Nodes proxy route
app.get("/etsy/seller-taxonomy/nodes", async (req, res) => {
  try {
    const apiKey = CLIENT_ID; // Use your Etsy API key from .env
    const response = await axios.get(
      "https://openapi.etsy.com/v3/application/seller-taxonomy/nodes",
      {
        headers: {
          "x-api-key": apiKey,
        },
      }
    );
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get shipping profiles for a shop
app.get("/shops/shipping-profiles", async (req, res) => {
  const access_token = getAccessTokenOr401(res);
  if (!access_token) return;

  let { shop_id } = req.params;

  shop_id = SHOP_ID;
  try {
    const endpoint = `https://openapi.etsy.com/v3/application/shops/${shop_id}/shipping-profiles`;
    const r = await axios.get(endpoint, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        "x-api-key": CLIENT_ID,
        "Content-Type": "application/json",
      },
    });
    return res.json(r.data);
  } catch (err) {
    console.error(
      "Get shipping profiles error:",
      err.response?.data || err.message
    );
    const status = err.response?.status || 500;
    return res
      .status(status)
      .json({ error: err.response?.data || err.message });
  }
});

app.get("/", (req, res) => res.send("Etsy backend demo running"));

// Start server
app.listen(PORT, () => {
  console.log(`Etsy backend demo running at ${BASE_URL}`);
  console.log(`1) Visit ${BASE_URL}/auth/login to start OAuth (PKCE) flow.`);
});
