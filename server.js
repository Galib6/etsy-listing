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

// Helper: refresh access token if expired
async function getValidAccessToken(res) {
  let access_token = getAccessTokenOr401(res);
  if (!access_token) return null;
  // Test token validity with a lightweight Etsy API call
  try {
    await axios.get("https://openapi.etsy.com/v3/application/users/me", {
      headers: {
        Authorization: `Bearer ${access_token}`,
        "x-api-key": CLIENT_ID,
        "Content-Type": "application/json",
      },
    });
    return access_token;
  } catch (err) {
    if (
      err.response?.data?.error === "invalid_token" ||
      err.response?.data?.error_description?.includes("expired")
    ) {
      // Try to refresh token
      try {
        const store = readTokens();
        const refresh_token = store?.etsy?.refresh_token;
        if (!refresh_token) return null;
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
        return tokens.access_token;
      } catch (refreshErr) {
        console.error(
          "Token refresh failed:",
          refreshErr.response?.data || refreshErr.message
        );
        res.status(401).send("Token refresh failed. Re-authenticate.");
        return null;
      }
    } else {
      throw err;
    }
  }
}

// 4) Create a draft listing
app.post("/listings", async (req, res) => {
  // Use new helper to get valid access token
  const access_token = await getValidAccessToken(res);
  if (!access_token) return;

  // Accept all Etsy listing properties from request body
  const {
    title,
    description,
    price,
    quantity,
    who_made,
    when_made,
    taxonomy_id,
    shipping_profile_id,
    return_policy_id,
    materials,
    shop_section_id,
    processing_min,
    processing_max,
    readiness_state_id,
    tags,
    styles,
    item_weight,
    item_length,
    item_width,
    item_height,
    item_weight_unit,
    item_dimensions_unit,
    is_personalizable,
    personalization_is_required,
    personalization_char_count_max,
    personalization_instructions,
    production_partner_ids,
    image_ids,
    is_supply,
    is_customizable,
    should_auto_renew,
    is_taxable,
    type,
    legacy,
    image_files, // array of image file paths
    sku,
    inventory, // allow full inventory object from payload
  } = req.body || {};

  // Basic validation for required fields and enums
  const errors = [];
  console.log(title, req.body);
  function validPositiveNumber(val) {
    return typeof val === "number" && val > 0;
  }
  if (!title || typeof title !== "string" || !title.trim())
    errors.push("title is required");
  if (!description || typeof description !== "string" || !description.trim())
    errors.push("description is required");
  if (price === undefined || isNaN(Number(price)) || Number(price) <= 0)
    errors.push("price must be a positive number");
  if (
    quantity === undefined ||
    isNaN(Number(quantity)) ||
    !Number.isInteger(Number(quantity)) ||
    Number(quantity) <= 0
  )
    errors.push("quantity must be a positive integer");
  if (!who_made || !["i_did", "someone_else", "collective"].includes(who_made))
    errors.push("who_made must be one of: i_did, someone_else, collective");
  if (
    !when_made ||
    ![
      "made_to_order",
      "2020_2024",
      "2010_2019",
      "2006_2009",
      "before_2006",
      "2000_2005",
      "1990s",
      "1980s",
      "1970s",
      "1960s",
      "1950s",
      "1940s",
      "1930s",
      "1920s",
      "1910s",
      "1900s",
      "1800s",
      "1700s",
      "before_1700",
    ].includes(when_made)
  )
    errors.push("Invalid when_made value");

  if (!sku) errors.push("Sku required");
  if (!taxonomy_id || isNaN(Number(taxonomy_id)) || Number(taxonomy_id) < 1)
    errors.push("taxonomy_id must be a positive integer");
  if (type && !["physical", "download", "both"].includes(type))
    errors.push("type must be one of: physical, download, both");
  if (item_weight_unit && !["oz", "lb", "g", "kg"].includes(item_weight_unit))
    errors.push("item_weight_unit must be one of: oz, lb, g, kg");
  if (
    item_dimensions_unit &&
    !["in", "ft", "mm", "cm", "m", "yd", "inches"].includes(
      item_dimensions_unit
    )
  )
    errors.push(
      "item_dimensions_unit must be one of: in, ft, mm, cm, m, yd, inches"
    );
  // Validate item_weight, item_length, item_width, item_height only for physical listings
  if (type === "physical") {
    if (item_weight !== undefined && !validPositiveNumber(item_weight))
      errors.push("item_weight must be a positive number if set");
    if (item_length !== undefined && !validPositiveNumber(item_length))
      errors.push("item_length must be a positive number if set");
    if (item_width !== undefined && !validPositiveNumber(item_width))
      errors.push("item_width must be a positive number if set");
    if (item_height !== undefined && !validPositiveNumber(item_height))
      errors.push("item_height must be a positive number if set");
  }
  console.log("error=>>>", errors);
  if (errors.length) return res.status(400).json({ errors });

  try {
    const endpoint = `https://api.etsy.com/v3/application/shops/${SHOP_ID}/listings`;
    // Build payload with all provided fields
    // Only include physical item fields if type is physical
    const payload = {
      title,
      description,
      price,
      quantity,
      who_made,
      when_made,
      taxonomy_id,
      shipping_profile_id,
      return_policy_id,
      materials,
      shop_section_id,
      processing_min,
      processing_max,
      readiness_state_id,
      tags,
      styles,
      is_personalizable,
      personalization_is_required,
      personalization_char_count_max,
      personalization_instructions,
      production_partner_ids,
      image_ids,
      is_supply,
      is_customizable,
      should_auto_renew,
      is_taxable,
      type,
      legacy,
    };
    if (type === "physical") {
      if (validPositiveNumber(item_weight)) payload.item_weight = item_weight;
      if (validPositiveNumber(item_length)) payload.item_length = item_length;
      if (validPositiveNumber(item_width)) payload.item_width = item_width;
      if (validPositiveNumber(item_height)) payload.item_height = item_height;
      if (item_weight_unit) payload.item_weight_unit = item_weight_unit;
      if (item_dimensions_unit)
        payload.item_dimensions_unit = item_dimensions_unit;
    }
    // Add inventory object for SKU support
    if (inventory && typeof inventory === "object") {
      payload.inventory = inventory;
    } else if (sku) {
      // If only sku is provided, build a minimal inventory object
      payload.inventory = {
        products: [
          {
            sku: sku,
            property_values: [],
            offerings: [
              {
                price: price,
                quantity: quantity,
                is_enabled: true,
              },
            ],
          },
        ],
      };
    }
    // Remove undefined fields
    Object.keys(payload).forEach(
      (key) => payload[key] === undefined && delete payload[key]
    );

    // Create the listing first
    const r = await axios.post(endpoint, payload, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        "x-api-key": CLIENT_ID,
        "Content-Type": "application/json",
      },
    });
    const listing = r.data;

    // Upload images if image_files is provided and is an array
    let uploadedImageIds = [];
    const isUrl = (str) => /^https?:\/\//i.test(str);
    const tmpDir = path.join(__dirname, "tmp_images");
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir);
    if (
      Array.isArray(image_files) &&
      image_files.length > 0 &&
      listing.listing_id &&
      SHOP_ID
    ) {
      // Wait 2 seconds before starting image upload to avoid Etsy concurrency error
      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Retry logic for image upload
      async function uploadImageWithRetry(filePath, i, maxRetries = 3) {
        let attempt = 0;
        let localPath = filePath;
        let tempFile = null;
        while (attempt < maxRetries) {
          try {
            if (isUrl(filePath)) {
              // Download image from URL to temp file
              const response = await axios.get(filePath, {
                responseType: "arraybuffer",
              });
              const ext = path.extname(filePath) || ".jpg";
              tempFile = path.join(
                tmpDir,
                `${crypto.randomBytes(8).toString("hex")}${ext}`
              );
              fs.writeFileSync(tempFile, response.data);
              localPath = tempFile;
            }
            const form = new FormData();
            form.append("image", fs.createReadStream(localPath));
            form.append("rank", String(i + 1));
            const imgEndpoint = `https://openapi.etsy.com/v3/application/shops/${SHOP_ID}/listings/${listing.listing_id}/images`;
            const imgResp = await axios.post(imgEndpoint, form, {
              headers: {
                Authorization: `Bearer ${access_token}`,
                "x-api-key": CLIENT_ID,
                ...form.getHeaders(),
              },
            });
            if (imgResp.data && imgResp.data.listing_image_id) {
              // Clean up temp file if created
              if (tempFile && fs.existsSync(tempFile)) {
                fs.unlinkSync(tempFile);
              }
              return String(imgResp.data.listing_image_id);
            }
          } catch (imgErr) {
            // Check for Etsy concurrency error
            const errorMsg = imgErr.response?.data?.error || imgErr.message;
            if (
              errorMsg &&
              errorMsg.includes("is being edited by another process") &&
              attempt < maxRetries - 1
            ) {
              // Wait 2 seconds and retry
              await new Promise((resolve) => setTimeout(resolve, 2000));
              attempt++;
              continue;
            }
            console.error(
              `Image upload failed for ${filePath} (attempt ${attempt + 1}):`,
              imgErr.response?.data || imgErr.message
            );
            break;
          } finally {
            // Clean up temp file if created
            if (tempFile && fs.existsSync(tempFile)) {
              fs.unlinkSync(tempFile);
            }
          }
          break;
        }
        return null;
      }

      // Sequential upload (one by one)
      uploadedImageIds = [];
      for (let i = 0; i < image_files.length; i++) {
        const filePath = image_files[i];
        const imageId = await uploadImageWithRetry(filePath, i);
        if (imageId) uploadedImageIds.push(imageId);
      }
    }

    // After draft listing is created, update inventory with SKU if provided
    let inventoryUpdateResult = null;
    let videoUploadResult = null;
    if (listing.listing_id && (sku || inventory)) {
      try {
        // Build inventory payload as in PUT /listings/:listing_id/inventory
        let productsArr = [];
        if (inventory && Array.isArray(inventory.products)) {
          productsArr = inventory.products;
        } else if (sku) {
          productsArr = [
            {
              sku: Number(sku),
              property_values: [],
              offerings: [
                {
                  price: price,
                  quantity: quantity,
                  is_enabled: true,
                },
              ],
            },
          ];
        }
        const inventoryPayload = {
          products: productsArr,
        };
        const endpointInventory = `https://openapi.etsy.com/v3/application/listings/${listing.listing_id}/inventory`;
        const rInventory = await axios.put(
          endpointInventory,
          inventoryPayload,
          {
            headers: {
              Authorization: `Bearer ${access_token}`,
              "x-api-key": CLIENT_ID,
              "Content-Type": "application/json",
            },
          }
        );
        inventoryUpdateResult = rInventory.data;

        // Upload video.mp4 after successful inventory update
        const videoPath = path.join(__dirname, "video.mp4");
        if (fs.existsSync(videoPath)) {
          try {
            const form = new FormData();
            form.append("video", fs.createReadStream(videoPath));
            form.append("name", "video.mp4");
            const videoEndpoint = `https://openapi.etsy.com/v3/application/shops/${SHOP_ID}/listings/${listing.listing_id}/videos`;
            const videoResp = await axios.post(videoEndpoint, form, {
              headers: {
                Authorization: `Bearer ${access_token}`,
                "x-api-key": CLIENT_ID,
                ...form.getHeaders(),
              },
            });
            videoUploadResult = videoResp.data;
          } catch (err) {
            console.error(
              "Video upload error:",
              err.response?.data || err.message
            );
            videoUploadResult = { error: err.response?.data || err.message };
          }
        }
      } catch (err) {
        console.error(
          "Inventory update after draft failed:",
          err.response?.data || err.message
        );
      }
    }

    // return the created listing, image IDs, and inventory update result
    return res.json({
      ok: true,
      listing,
      listing_images_id: uploadedImageIds,
      inventory: inventoryUpdateResult,
      video: videoUploadResult,
    });
  } catch (err) {
    console.log(err);
    console.log("Full API error object:", err);
    if (err.response) {
      console.log("API error response data:", err.response.data);
      console.log("API error response status:", err.response.status);
      console.log("API error response headers:", err.response.headers);
    }
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
  const access_token = getValidAccessToken(res);
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

// health
// Proxy Etsy API: Get authenticated user info
app.get("/return-policies", async (req, res) => {
  const access_token = getValidAccessToken(res);
  if (!access_token) return;

  try {
    const endpoint = `https://openapi.etsy.com/v3/application/shops/${SHOP_ID}/policies/return`;
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
