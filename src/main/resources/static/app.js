// The web shell (console step 0): OIDC authorization code with PKCE against the global realm, the token
// kept in memory only, GET /api/me, and navigation by role. The React app replaces it later (PLAN.md).
// Tenant roles only (user decision D2, 2026-11-03): the caller's own tenant (and a parent's sub-tenants),
// never every tenant; staff work in parity-cc-tools.
"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  let token = null;
  let config = null;

  const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const random = (n) => b64url(crypto.getRandomValues(new Uint8Array(n)));

  async function signIn() {
    const verifier = random(32);
    const state = random(16);
    const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
    sessionStorage.setItem("pkce", JSON.stringify({ verifier, state }));
    const p = new URLSearchParams({ client_id: config.client_id, redirect_uri: location.origin + "/", response_type: "code",
      scope: "openid", state, code_challenge: challenge, code_challenge_method: "S256" });
    location.assign(config.issuer + "/protocol/openid-connect/auth?" + p);
  }

  async function redeem(code, state) {
    const saved = JSON.parse(sessionStorage.getItem("pkce") || "{}");
    sessionStorage.removeItem("pkce");
    history.replaceState(null, "", "/");
    if (!saved.state || saved.state !== state) throw new Error("the sign-in didn't match: try again");
    const body = new URLSearchParams({ grant_type: "authorization_code", client_id: config.client_id, code,
      redirect_uri: location.origin + "/", code_verifier: saved.verifier });
    const r = await fetch(config.issuer + "/protocol/openid-connect/token", { method: "POST", body });
    if (!r.ok) throw new Error("the sign-in failed");
    token = (await r.json()).access_token;
  }

  async function api(path) {
    const r = await fetch(path, { headers: { Authorization: "Bearer " + token, Accept: "application/json" } });
    if (r.status === 401) { token = null; render(); throw new Error("signed out"); }
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).code || ("HTTP " + r.status));
    return r.json();
  }

  function table(rows, cols) {
    const t = document.createElement("table");
    const head = t.createTHead().insertRow();
    cols.forEach((c) => { const th = document.createElement("th"); th.textContent = c; head.appendChild(th); });
    const body = t.createTBody();
    rows.forEach((row) => { const tr = body.insertRow(); cols.forEach((c) => { tr.insertCell().textContent = row[c] == null ? "" : String(row[c]); }); });
    return t;
  }

  const tenant = (id) => api("/api/tenants/" + encodeURIComponent(id));
  let me = null;

  const views = {
    // The caller's tenant, and for its tenant admin its sub-tenants (an enterprise parent's).
    tenant: async () => {
      const own = await tenant(me.tenant_id);
      const rows = [own];
      // A suspended sub-tenant answers 403: listed by id, without its details.
      if (me.roles.includes("tenant-admin")) rows.push(...await Promise.all((own.sub_tenants || []).map((id) => tenant(id).catch(() => ({ tenant_id: id })))));
      return table(rows, ["tenant_id", "name", "tier", "parent"]);
    },
    audit: async () => table((await api("/api/audit")).rows, ["at", "actor", "tenant_id", "action", "phase", "outcome"]),
  };

  async function show(view) {
    const main = $("main");
    main.textContent = "Loading…";
    try { main.replaceChildren(await views[view]()); } catch (e) { main.innerHTML = ""; const p = document.createElement("p"); p.className = "error"; p.textContent = e.message; main.appendChild(p); }
  }

  async function render() {
    const nav = $("nav");
    if (!token) {
      me = null;
      $("signin").hidden = false; $("signout").hidden = true; nav.hidden = true; $("who").textContent = "";
      $("main").textContent = "Sign in to continue.";
      return;
    }
    me = await api("/api/me");
    $("signin").hidden = true; $("signout").hidden = false;
    $("who").textContent = me.username + " · " + me.tenant_id + " · " + me.roles.join(", ");
    nav.replaceChildren();
    const items = [];
    if (me.roles.includes("tenant-admin")) items.push(["tenant", "My tenant"], ["audit", "Audit log"]);
    else if (me.roles.includes("supervisor")) items.push(["tenant", "My tenant"]);
    items.forEach(([v, label]) => { const a = document.createElement("a"); a.href = "#" + v; a.textContent = label; a.onclick = (e) => { e.preventDefault(); show(v); }; nav.appendChild(a); });
    nav.hidden = false;
    if (items.length) show(items[0][0]); else $("main").textContent = "Nothing here for your role.";
  }

  async function start() {
    config = await (await fetch("/api/config")).json();
    $("signin").onclick = signIn;
    $("signout").onclick = () => { token = null; location.assign(config.issuer + "/protocol/openid-connect/logout?" + new URLSearchParams({ client_id: config.client_id, post_logout_redirect_uri: location.origin + "/" })); };
    const q = new URLSearchParams(location.search);
    if (q.get("code")) {
      try { await redeem(q.get("code"), q.get("state")); } catch (e) { $("main").textContent = e.message; }
    }
    await render();
  }
  start();
})();
