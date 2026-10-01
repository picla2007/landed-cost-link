
// POST /api/analyze  { url: "https://..." }
// Lee la ficha de un producto de cualquier plataforma y devuelve título, precio y datos útiles.
// Variables de entorno: ANTHROPIC_API_KEY (obligatoria para la lectura con IA), ANALYZE_MODEL (opcional)

const dns = require("dns").promises;
const net = require("net");

// ---------- Límite simple por IP (en memoria, best effort) ----------
const hits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(function (t) { return now - t < 10 * 60 * 1000; });
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) hits.clear();
  return arr.length > 20;
}

// ---------- Seguridad: no permitir direcciones internas ----------
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    return p[0] === 0 || p[0] === 10 || p[0] === 127 ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === "::1" || l === "::" || l.indexOf("fc") === 0 || l.indexOf("fd") === 0 ||
      l.indexOf("fe80") === 0 || l.indexOf("::ffff:") === 0;
  }
  return true;
}

async function assertPublic(hostname) {
  if (hostname === "localhost" || /\.local$|\.internal$/i.test(hostname)) throw new Error("host privado");
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) throw new Error("host privado");
    return;
  }
  const addrs = await dns.lookup(hostname, { all: true });
  for (let i = 0; i < addrs.length; i++) {
    if (isPrivateIp(addrs[i].address)) throw new Error("host privado");
  }
}

// ---------- Descarga de la página ----------
async function fetchPage(startUrl) {
  let current = startUrl;
  for (let i = 0; i < 4; i++) {
    const u = new URL(current);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("protocolo no permitido");
    await assertPublic(u.hostname);
    const ctrl = new AbortController();
    const timer = setTimeout(function () { ctrl.abort(); }, 5000);
    try {
      const r = await fetch(u.toString(), {
        redirect: "manual",
        signal: ctrl.signal,
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml",
          "Accept-Language": "es-AR,es;q=0.9,en;q=0.8"
        }
      });
      const loc = r.headers.get("location");
      if (r.status >= 300 && r.status < 400 && loc) {
        current = new URL(loc, u).toString();
        continue;
      }
      const html = (await r.text()).slice(0, 1500000);
      return { status: r.status, html: html, finalUrl: u.toString() };
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error("demasiadas redirecciones");
}

// ---------- Extracción sin IA ----------
function decodeEntities(s) {
  return String(s)
    .replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#0?39;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&nbsp;/g, " ");
}

function metaContent(html, key) {
  const re1 = new RegExp('<meta[^>]+(?:property|name)=["\']' + key + '["\'][^>]*content=["\']([^"\']*)["\']', "i");
  const re2 = new RegExp('<meta[^>]+content=["\']([^"\']*)["\'][^>]*(?:property|name)=["\']' + key + '["\']', "i");
  const m = html.match(re1) || html.match(re2);
  return m ? decodeEntities(m[1]) : null;
}

function parseNum(v) {
  if (typeof v === "number") return isFinite(v) ? v : null;
  let s = String(v).replace(/[^\d.,]/g, "");
  if (!s) return null;
  const lastC = s.lastIndexOf(",");
  const lastD = s.lastIndexOf(".");
  if (lastC > -1 && lastD > -1) {
    s = lastC > lastD ? s.replace(/\./g, "").replace(",", ".") : s.replace(/,/g, "");
  } else if (lastC > -1) {
    s = (s.length - lastC - 1 === 3) ? s.replace(/,/g, "") : s.replace(",", ".");
  } else if (s.split(".").length > 2) {
    s = s.replace(/\./g, "");
  }
  const n = parseFloat(s);
  return isFinite(n) ? n : null;
}

function findProduct(node) {
  if (!node) return null;
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const p = findProduct(node[i]);
      if (p) return p;
    }
    return null;
  }
  if (typeof node === "object") {
    const t = node["@type"];
    const types = Array.isArray(t) ? t : [t];
    if (types.indexOf("Product") !== -1) return node;
    if (node["@graph"]) return findProduct(node["@graph"]);
  }
  return null;
}

function extractStructured(html) {
  const out = { titulo: null, precio: null, moneda: null, imagen: null };
  const re = /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      const prod = findProduct(JSON.parse(m[1].trim()));
      if (prod) {
        out.titulo = prod.name || out.titulo;
        const img = Array.isArray(prod.image) ? prod.image[0] : prod.image;
        out.imagen = (img && (img.url || img)) || out.imagen;
        const o = Array.isArray(prod.offers) ? prod.offers[0] : prod.offers;
        if (o) {
          const p = o.price != null ? o.price : (o.lowPrice != null ? o.lowPrice : null);
          if (p != null) out.precio = parseNum(p);
          out.moneda = o.priceCurrency || out.moneda;
        }
        break;
      }
    } catch (e) { /* JSON inválido: se ignora */ }
  }
  out.titulo = out.titulo || metaContent(html, "og:title") || ((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || null);
  out.imagen = out.imagen || metaContent(html, "og:image");
  if (out.precio == null) {
    const p = metaContent(html, "product:price:amount") || metaContent(html, "og:price:amount");
    if (p) out.precio = parseNum(p);
  }
  out.moneda = out.moneda || metaContent(html, "product:price:currency") || metaContent(html, "og:price:currency");
  if (out.titulo) out.titulo = decodeEntities(String(out.titulo)).trim();
  return out;
}

function pageText(html) {
  return decodeEntities(
    html
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<(script|style|noscript|svg)[\s\S]*?<\/\1>/gi, " ")
      .replace(/<[^>]+>/g, " ")
  ).replace(/\s+/g, " ").trim();
}

// ---------- Lectura con IA ----------
async function askClaude(datos, texto, url) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return null;
  const prompt =
    "URL: " + url + "\n" +
    "Datos estructurados detectados: " + JSON.stringify(datos) + "\n\n" +
    "Texto de la página:\n" + texto.slice(0, 9000) + "\n\n" +
    "Extraé la información del producto y devolvé SOLO este JSON:\n" +
    "{\n" +
    '  "titulo": string,\n' +
    '  "precio_unitario": number o null (precio por unidad para la cantidad mínima de compra, o el precio fijo si no hay escalones),\n' +
    '  "moneda": código ISO 4217 como USD, ARS, CNY, EUR,\n' +
    '  "precios_escalonados": [{"desde": cantidad, "precio": precio por unidad}] o [],\n' +
    '  "pedido_minimo": number o null,\n' +
    '  "categoria": string corta en español,\n' +
    '  "peso_kg_unidad": number o null (solo si la página lo indica)\n' +
    "}\n" +
    "Si un dato no figura en la página, usá null. No inventes precios ni pesos.";
  const ctrl = new AbortController();
  const timer = setTimeout(function () { ctrl.abort(); }, 4500);
  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      signal: ctrl.signal,
      headers: {
        "content-type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: process.env.ANALYZE_MODEL || "claude-haiku-4-5-20251001",
        max_tokens: 700,
        system: "Sos un extractor de datos de fichas de producto de e-commerce. Respondé únicamente con un objeto JSON válido, sin texto extra ni bloques de código.",
        messages: [{ role: "user", content: prompt }]
      })
    });
    if (!r.ok) return null;
    const data = await r.json();
    let txt = "";
    (data.content || []).forEach(function (b) { if (b.type === "text") txt += b.text; });
    const a = txt.indexOf("{");
    const b = txt.lastIndexOf("}");
    if (a === -1 || b === -1) return null;
    return JSON.parse(txt.slice(a, b + 1));
  } catch (e) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ---------- Handler ----------
function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

async function handler(req, res) {
  setCors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, mensaje: "Método no permitido." });

  const ip = String(req.headers["x-forwarded-for"] || "x").split(",")[0].trim();
  if (rateLimited(ip)) return res.status(429).json({ ok: false, mensaje: "Demasiados intentos. Probá de nuevo en unos minutos." });

  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch (e) { body = {}; } }
  const url = body && typeof body.url === "string" ? body.url.trim() : "";
  try { new URL(url); } catch (e) {
    return res.status(400).json({ ok: false, mensaje: "El link no es válido." });
  }

  let page;
  try {
    page = await fetchPage(url);
  } catch (e) {
    return res.status(200).json({ ok: false, mensaje: "No pude abrir ese link. Revisalo o cargá el precio a mano." });
  }

  if (page.status === 404) return res.status(200).json({ ok: false, mensaje: "Ese link no existe o la publicación fue eliminada." });

  const datos = extractStructured(page.html);
  const texto = pageText(page.html);
  const bloqueada = [401, 403, 429, 503].indexOf(page.status) !== -1 ||
    /captcha|verify you are human|access denied|unusual traffic/i.test(texto.slice(0, 3000));
  if (bloqueada || (texto.length < 300 && datos.precio == null)) {
    return res.status(200).json({
      ok: false,
      mensaje: "Esta plataforma bloquea la lectura automática o carga el precio con JavaScript. Cargá el precio a mano."
    });
  }

  const ai = await askClaude(datos, texto, page.finalUrl);
  const precio = (ai && ai.precio_unitario != null ? parseNum(ai.precio_unitario) : null) || datos.precio;
  if (precio == null) {
    return res.status(200).json({
      ok: false,
      mensaje: "Encontré la página pero no pude identificar el precio. Cargalo a mano."
    });
  }

  const tiers = ai && Array.isArray(ai.precios_escalonados)
    ? ai.precios_escalonados
        .map(function (t) { return { desde: parseNum(t.desde), precio: parseNum(t.precio) }; })
        .filter(function (t) { return t.desde != null && t.precio != null; })
        .sort(function (a, b) { return a.desde - b.desde; })
    : [];

  return res.status(200).json({
    ok: true,
    fuente: ai ? "ia" : "estructurado",
    producto: {
      plataforma: new URL(page.finalUrl).hostname.replace(/^www\./, ""),
      titulo: (ai && ai.titulo) || datos.titulo || "Producto sin título",
      imagen: datos.imagen || null,
      precio_unitario: precio,
      moneda: ((ai && ai.moneda) || datos.moneda || "USD").toUpperCase(),
      precios_escalonados: tiers,
      pedido_minimo: ai && ai.pedido_minimo != null ? parseNum(ai.pedido_minimo) : null,
      categoria: (ai && ai.categoria) || null,
      peso_kg_unidad: ai && ai.peso_kg_unidad != null ? parseNum(ai.peso_kg_unidad) : null
    }
  });
}

module.exports = handler;
module.exports._test = { extractStructured: extractStructured, parseNum: parseNum, assertPublic: assertPublic, pageText: pageText };
