import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const secret = () => process.env.ADMIN_PASSWORD || "";
const sign = (t) => crypto.createHmac("sha256", "bk|" + secret()).update(String(t)).digest("hex");
const mkToken = () => { const t = Date.now() + 12 * 3600e3; return t + "." + sign(t); };
const valid = (tk) => {
  if (!secret() || typeof tk !== "string") return false;
  const [t, s] = tk.split(".");
  if (!t || !s || Number(t) < Date.now()) return false;
  const a = Buffer.from(sign(t)), b = Buffer.from(s);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const J = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const str = (v, n) => String(v ?? "").slice(0, n);
let fails = 0, lockUntil = 0;

export default async (req) => {
  const store = getStore("shop");
  if (req.method === "GET") {
    const im = new URL(req.url).searchParams.get("img");
    if (im) {
      if (!/^i\d+$/.test(im)) return new Response("", { status: 404 });
      const e = await store.getWithMetadata(im, { type: "arrayBuffer" });
      if (!e) return new Response("", { status: 404 });
      return new Response(e.data, { headers: { "content-type": e.metadata?.type || "image/jpeg", "cache-control": "public, max-age=31536000, immutable" } });
    }
    const products = (await store.get("products", { type: "json" })) || [];
    const settings = (await store.get("settings", { type: "json" })) || { wa: "" };
    return J({ products, settings });
  }
  if (req.method !== "POST") return J({ error: "method" }, 405);
  let b;
  try { b = await req.json(); } catch { return J({ error: "bad request" }, 400); }

  if (b.a === "login") {
    if (!secret()) return J({ error: "لم يتم ضبط ADMIN_PASSWORD في إعدادات Netlify بعد." }, 503);
    if (Date.now() < lockUntil) return J({ error: "محاولات كثيرة. انتظر دقيقة ثم حاول." }, 429);
    const a = Buffer.from(String(b.pw || "")), c = Buffer.from(secret());
    if (!(a.length === c.length && crypto.timingSafeEqual(a, c))) {
      if (++fails >= 5) { lockUntil = Date.now() + 60000; fails = 0; }
      await new Promise((r) => setTimeout(r, 700));
      return J({ error: "كلمة السر غير صحيحة." }, 401);
    }
    fails = 0;
    return J({ token: mkToken() });
  }

  if (!valid(b.token)) return J({ error: "401" }, 401);

  if (b.a === "save") {
    if (!Array.isArray(b.products) || b.products.length > 500) return J({ error: "بيانات غير صالحة" }, 400);
    const products = b.products.map((p) => ({
      id: str(p.id, 40), name: str(p.name, 120), price: Math.max(0, Number(p.price) || 0),
      cat: str(p.cat, 40), sizes: str(p.sizes, 80), desc: str(p.desc, 600),
      img: /^\/api\?img=i\d+$/.test(p.img || "") ? p.img : "",
    }));
    await store.setJSON("products", products);
    await store.setJSON("settings", { wa: str(b.settings?.wa, 20).replace(/\D/g, "") });
    return J({ ok: true });
  }

  if (b.a === "img") {
    const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(b.data || "");
    if (!m || !/^i\d+$/.test(b.id || "")) return J({ error: "صورة غير صالحة" }, 400);
    const buf = Buffer.from(m[2], "base64");
    if (buf.length > 2e6) return J({ error: "الصورة كبيرة جدًا" }, 400);
    await store.set(b.id, new Blob([buf], { type: m[1] }), { metadata: { type: m[1] } });
    return J({ ok: true });
  }
  return J({ error: "unknown" }, 400);
};

export const config = { path: "/api" };
