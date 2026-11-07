const COOKIE_NAME = "auth_session";
const SESSION_SECONDS = 7 * 24 * 60 * 60;

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sign(expiry, password) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`auth:${expiry}`)
  );

  return base64url(new Uint8Array(signature));
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }

  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return difference === 0;
}

function safeReturnTo(value, baseUrl) {
  if (typeof value !== "string") return "/";

  try {
    const base = new URL(baseUrl);
    const target = new URL(value, base);

    if (
      target.origin !== base.origin ||
      target.pathname.startsWith("/__auth/")
    ) {
      return "/";
    }

    return target.pathname + target.search + target.hash;
  } catch {
    return "/";
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const item = cookies.split(";").map(v => v.trim())
    .find(v => v.startsWith(name + "="));

  return item ? item.slice(name.length + 1) : "";
}

async function isAuthorized(request, password) {
  const token = getCookie(request, COOKIE_NAME);
  const [expiry, signature] = token.split(".");

  if (!expiry || !signature || !/^\d+$/.test(expiry)) return false;
  if (Number(expiry) < Math.floor(Date.now() / 1000)) return false;

  const expected = await sign(expiry, password);
  return constantTimeEqual(signature, expected);
}

async function samePassword(a, b) {
  const encoder = new TextEncoder();

  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b))
  ]);

  const x = new Uint8Array(hashA);
  const y = new Uint8Array(hashB);

  let difference = 0;
  for (let i = 0; i < x.length; i++) {
    difference |= x[i] ^ y[i];
  }

  return difference === 0;
}

function loginPage(returnTo, baseUrl, error = false) {
  const safePath = escapeHtml(safeReturnTo(returnTo, baseUrl));

  return new Response(`<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Вход | Химия ЕГЭ</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;
font-family:Arial,sans-serif;background:#f3f5f1;color:#263329;padding:20px}
main{width:100%;max-width:380px;background:white;padding:32px;
border-radius:16px;box-shadow:0 8px 30px #0000000d}
h1{font-size:23px;margin:0 0 10px}
p{color:#667267;line-height:1.5}
input,button{width:100%;padding:14px;border-radius:9px;font-size:16px}
input{border:1px solid #cbd3ca;margin:12px 0}
button{border:0;background:#536b53;color:white;font-weight:600;cursor:pointer}
</style>
</head>
<body>
<main>
<h1>Вход на учебную платформу</h1>
<p>Введите пароль, чтобы открыть материалы по химии.</p>
${error ? '<p style="color:#b42318">Неверный пароль. Попробуйте ещё раз.</p>' : ''}
<form method="POST" action="/__auth/login">
<input type="hidden" name="returnTo" value="${safePath}">
<input type="password" name="password" placeholder="Пароль" required autofocus>
<button type="submit">Войти</button>
</form>
</main>
</body>
</html>`, {
    status: error ? 401 : 200,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

export async function onRequest(context) {
  const { request, env } = context;
  const password = env.ACCESS_PASSWORD;

  if (!password) {
    return new Response(
      "Не настроен секрет ACCESS_PASSWORD в Cloudflare Pages.",
      { status: 500 }
    );
  }

  const url = new URL(request.url);

  if (url.pathname === "/__auth/login" && request.method === "POST") {
    const form = await request.formData();
    const entered = String(form.get("password") || "");
    const returnTo = safeReturnTo(form.get("returnTo"), request.url);

    if (!(await samePassword(entered, password))) {
      return loginPage(returnTo, request.url, true);
    }

    const expiry = String(
      Math.floor(Date.now() / 1000) + SESSION_SECONDS
    );

    const signature = await sign(expiry, password);
    const token = `${expiry}.${signature}`;

    return new Response(null, {
      status: 303,
      headers: {
        "Location": returnTo,
        "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_SECONDS}`,
        "Cache-Control": "no-store"
      }
    });
  }

  if (await isAuthorized(request, password)) {
    return context.next();
  }

  return loginPage(url.pathname + url.search, request.url);
}
