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
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
];
function pausa(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

async function fetchPage(startUrl, ua) {
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
          "User-Agent": ua || USER_AGENTS[0],
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
const NAMED = {
  amp: "&", quot: '"', apos: "'", lt: "<", gt: ">", nbsp: " ",
  ntilde: "ñ", Ntilde: "Ñ", aacute: "á", eacute: "é", iacute: "í", oacute: "ó", uacute: "ú",
  Aacute: "Á", Eacute: "É", Iacute: "Í", Oacute: "Ó", Uacute: "Ú", uuml: "ü", Uuml: "Ü",
  agrave: "à", egrave: "è", ccedil: "ç", iexcl: "¡", iquest: "¿", ordm: "º", ordf: "ª",
  copy: "©", reg: "®", deg: "°", euro: "€", ndash: "–", mdash: "—", hellip: "…",
  laquo: "«", raquo: "»", lsquo: "‘", rsquo: "’", ldquo: "“", rdquo: "”", times: "×", middot: "·"
};
function decodeEntities(s) {
  return String(s)
    .replace(/&#x([0-9a-f]+);/gi, function (m, h) { try { return String.fromCodePoint(parseInt(h, 16)); } catch (e) { return m; } })
    .replace(/&#(\d+);/g, function (m, d) { try { return String.fromCodePoint(parseInt(d, 10)); } catch (e) { return m; } })
    .replace(/&([a-zA-Z]+);/g, function (m, n) { return Object.prototype.hasOwnProperty.call(NAMED, n) ? NAMED[n] : m; });
}

function cleanTitle(t) {
  return decodeEntities(String(t || ""))
    .replace(/\s*[-–|]\s*(?:Buy [^-|]*? on |Compra[r]? [^-|]*? en )?Alibaba\.com\s*$/i, "")
    .replace(/\s+/g, " ").trim();
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
  if (!key) return { ai: null, motivo: "sin_clave" };
  const prompt =
    "URL: " + url + "\n" +
    "Datos estructurados detectados: " + JSON.stringify(datos) + "\n\n" +
    "Texto de la página:\n" + texto.slice(0, 14000) + "\n\n" +
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
  const timer = setTimeout(function () { ctrl.abort(); }, 20000);
  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      signal: ctrl.signal,
      headers: {
        "content-type": "application/json",
        "x-api-key": key.trim(),
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: process.env.ANALYZE_MODEL || "claude-haiku-4-5-20251001",
        max_tokens: 700,
        system: "Sos un extractor de datos de fichas de producto de e-commerce. Respondé únicamente con un objeto JSON válido, sin texto extra ni bloques de código.",
        messages: [{ role: "user", content: prompt }]
      })
    });
    if (!r.ok) {
      let t = "";
      try { t = (await r.text()).slice(0, 300); } catch (e) { /* sin cuerpo */ }
      console.error("Anthropic API error", r.status, t);
      return { ai: null, motivo: "http_" + r.status };
    }
    const data = await r.json();
    let txt = "";
    (data.content || []).forEach(function (b) { if (b.type === "text") txt += b.text; });
    const i = txt.indexOf("{");
    const j = txt.lastIndexOf("}");
    if (i === -1 || j === -1) return { ai: null, motivo: "sin_json" };
    return { ai: JSON.parse(txt.slice(i, j + 1)), motivo: null };
  } catch (e) {
    console.error("askClaude falló:", e && e.message);
    return { ai: null, motivo: "error" };
  } finally {
    clearTimeout(timer);
  }
}

// ---------- Lectura sin IA: escalones de precio, peso y título ----------
function fallbackParse(raw) {
  const flat = raw.replace(/\s+/g, " ");
  const re = /(?:US\s?\$|USD|\$)\s?(\d[\d.,]*)\s*(?:[\/·|,]\s*)?(?:(?:≥|>=|>)\s?(\d[\d,]*)|(\d[\d,]*)\s?(?:-|–|to)\s?(\d[\d,]*))\s*(?:pieces?|piezas?|pcs|units?|unidades?|sets?|pairs?|bags?|lots?)/gi;
  const seen = {};
  const tiers = [];
  let m;
  while ((m = re.exec(flat)) !== null) {
    const precio = parseNum(m[1]);
    const desde = parseNum(m[2] != null ? m[2] : m[3]);
    if (precio != null && desde != null && !seen[desde]) {
      seen[desde] = true;
      tiers.push({ desde: desde, precio: precio });
    }
  }
  tiers.sort(function (x, y) { return x.desde - y.desde; });

  let peso = null;
  const w = flat.match(/(?:Gross Weight|Peso bruto)\s*:?\s*([\d.,]+)\s*kg/i) ||
    flat.match(/(?:Net Weight|Peso neto)\s*:?\s*([\d.,]+)\s*kg/i);
  if (w) peso = parseNum(w[1]);

  let titulo = null;
  if (raw.indexOf("\n") !== -1) {
    const lines = raw.split(/\r?\n/).map(function (l) { return l.trim(); });
    let stop = lines.findIndex(function (l) { return /^(?:US\s?\$|USD|\$)\s?\d/.test(l); });
    if (stop === -1) stop = lines.length;
    const NO_TITULO = /^(?:no reviews|\d+(?:\.\d+)?\s*\/\s*5|store rating|main markets|response time|on-time|reorder|supplier|custom|minor|drawing|sample|full custom|verified|gold|select|photos|video|next slide|guardar|copiar|generador|id del|buscar|sell on|help center|about alibaba|deliver to|what are you)/i;
    for (let i = stop - 1; i >= 0; i--) {
      const l = lines[i];
      if (l.length < 25 || l.length > 220) continue;
      if (l.indexOf("](") !== -1 || l.indexOf("http") !== -1 || /^[*\d#]/.test(l) || NO_TITULO.test(l)) continue;
      titulo = l;
      break;
    }
  }
  return { tiers: tiers, peso: peso, titulo: titulo };
}

function motivoMensaje(m) {
  if (m === "sin_clave") return "Falta la clave de la IA: agregá ANTHROPIC_API_KEY en Vercel (Settings → Environment Variables) y hacé un Redeploy.";
  if (m === "http_401") return "La clave ANTHROPIC_API_KEY no es válida. Revisá que esté bien copiada, sin espacios ni comillas.";
  if (m === "http_404") return "El modelo configurado no existe. Borrá la variable ANALYZE_MODEL en Vercel o poné un modelo válido.";
  if (m === "http_429" || m === "http_529") return "La API de Anthropic está saturada o llegaste al límite. Probá de nuevo en un rato.";
  if (m && m.indexOf("http_") === 0) return "La API de Anthropic respondió con error " + m.slice(5) + ". Revisá la clave y el saldo de tu cuenta.";
  return "No pude identificar el precio en el texto. Asegurate de copiar la parte con los precios, o cargalo a mano.";
}

// ---------- Scraper opcional (para plataformas que bloquean, ej. Alibaba) ----------
// Usa ScrapingBee si existe SCRAPINGBEE_API_KEY. Consume créditos de ese servicio.
async function fetchViaScraper(url) {
  const key = process.env.SCRAPINGBEE_API_KEY;
  if (!key) return null;
  const ctrl = new AbortController();
  const timer = setTimeout(function () { ctrl.abort(); }, 40000);
  try {
    const api = "https://app.scrapingbee.com/api/v1/?api_key=" + encodeURIComponent(key) +
      "&url=" + encodeURIComponent(url) + "&render_js=true&premium_proxy=true&country_code=us";
    const r = await fetch(api, { signal: ctrl.signal });
    if (!r.ok) return null;
    return { status: 200, html: (await r.text()).slice(0, 1500000), finalUrl: url };
  } catch (e) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function leer(page) {
  const datos = extractStructured(page.html);
  const texto = pageText(page.html);
  const bloqueada = [401, 403, 429, 503].indexOf(page.status) !== -1 ||
    /captcha|verify you are human|access denied|unusual traffic|slide to verify/i.test(texto.slice(0, 3000)) ||
    (texto.length < 300 && datos.precio == null);
  return { datos: datos, texto: texto, bloqueada: bloqueada };
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
  body = body || {};
  const url = typeof body.url === "string" ? body.url.trim() : "";
  const pegadoRaw = typeof body.texto === "string" ? body.texto.slice(0, 60000) : "";
  const pegado = pegadoRaw.replace(/\s+/g, " ").trim();

  let datos = { titulo: null, precio: null, moneda: null, imagen: null };
  let texto = "";
  let finalUrl = url;

  if (pegado.length >= 50) {
    // Modo texto pegado: no se descarga nada, no hay bloqueo posible
    texto = pegado;
  } else {
    try { new URL(url); } catch (e) {
      return res.status(400).json({ ok: false, mensaje: "El link no es válido." });
    }
    let page = null;
    let r = { bloqueada: true };
    let detalle = "sin respuesta";
    for (let i = 0; i < USER_AGENTS.length; i++) {
      try {
        page = await fetchPage(url, USER_AGENTS[i]);
      } catch (e) {
        page = null;
        detalle = "sin respuesta (" + (e && e.name === "AbortError" ? "tiempo agotado" : (e && e.message) || "error") + ")";
      }
      if (page && page.status === 404) {
        return res.status(200).json({ ok: false, mensaje: "Ese link no existe o la publicación fue eliminada." });
      }
      if (page) {
        r = leer(page);
        detalle = "HTTP " + page.status + ", " + r.texto.length + " caracteres";
        if (!r.bloqueada) break;
      }
      if (i < USER_AGENTS.length - 1) await pausa(600);
    }
    if (r.bloqueada) {
      const via = await fetchViaScraper(url);
      if (via) { page = via; r = leer(via); detalle = "servicio de scraping"; }
    }
    if (r.bloqueada || !page) {
      return res.status(200).json({
        ok: false,
        sugerirTexto: true,
        detalle: detalle,
        mensaje: "Esta plataforma bloquea la lectura automática. Pegá abajo el texto de la página y lo analizo igual."
      });
    }
    datos = r.datos;
    texto = r.texto;
    finalUrl = page.finalUrl;
  }

  const respuesta = await askClaude(datos, texto, finalUrl || "(texto pegado)");
  const ai = respuesta.ai;
  const fb = fallbackParse(pegado.length >= 50 ? pegadoRaw : texto);

  let tiers = ai && Array.isArray(ai.precios_escalonados)
    ? ai.precios_escalonados
        .map(function (t) { return { desde: parseNum(t.desde), precio: parseNum(t.precio) }; })
        .filter(function (t) { return t.desde != null && t.precio != null; })
        .sort(function (a, b) { return a.desde - b.desde; })
    : [];
  // Si el texto trae escalones claros, esos mandan sobre lo que devuelva la IA
  if (fb.tiers.length) tiers = fb.tiers;

  let precio = tiers.length ? tiers[0].precio : null;
  if (precio == null) precio = (ai && ai.precio_unitario != null ? parseNum(ai.precio_unitario) : null) || datos.precio;
  if (precio == null) {
    return res.status(200).json({
      ok: false,
      sugerirTexto: true,
      mensaje: motivoMensaje(respuesta.motivo)
    });
  }

  let plataforma = "texto pegado";
  try { plataforma = new URL(finalUrl).hostname.replace(/^www\./, ""); } catch (e) { /* sin url */ }

  return res.status(200).json({
    ok: true,
    fuente: ai ? "ia" : (fb.tiers.length ? "texto" : "estructurado"),
    producto: {
      plataforma: plataforma,
      titulo: cleanTitle((ai && ai.titulo) || fb.titulo || datos.titulo) || "Producto sin título",
      imagen: datos.imagen || null,
      precio_unitario: precio,
      moneda: (fb.tiers.length ? "USD" : ((ai && ai.moneda) || datos.moneda || "USD")).toUpperCase(),
      precios_escalonados: tiers,
      pedido_minimo: ai && ai.pedido_minimo != null ? parseNum(ai.pedido_minimo) : (tiers.length && tiers[0].desde > 1 ? tiers[0].desde : null),
      categoria: (ai && ai.categoria) || null,
      peso_kg_unidad: fb.peso != null ? fb.peso : (ai && ai.peso_kg_unidad != null ? parseNum(ai.peso_kg_unidad) : null),
      aviso: ai ? null : motivoMensaje(respuesta.motivo)
    }
  });
}

module.exports = handler;
module.exports._test = { cleanTitle: cleanTitle, decodeEntities: decodeEntities, fallbackParse: fallbackParse, extractStructured: extractStructured, parseNum: parseNum, assertPublic: assertPublic, pageText: pageText };
