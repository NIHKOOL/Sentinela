// Shared helpers for all Sentinela pages.
const S = (() => {
  async function api(path, options = {}) {
    const init = { ...options, headers: { "Content-Type": "application/json" } };
    if (init.body !== undefined && typeof init.body !== "string") init.body = JSON.stringify(init.body);
    const response = await fetch(`/api/v1${path}`, init);
    if (response.status === 204) return null;
    const data = await response.json().catch(() => null);
    if (!response.ok) {
      const detail = data && data.detail;
      const message = Array.isArray(detail)
        ? detail.map((d) => `${d.loc.at(-1)}: ${d.msg}`).join("; ")
        : detail || response.statusText;
      throw new Error(message);
    }
    return data;
  }

  // Build elements with textContent only: event data must never be parsed as HTML.
  function el(tag, props = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "text") node.textContent = value;
      else if (key === "class") node.className = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? "" : value);
    }
    for (const child of [].concat(children)) if (child !== null && child !== undefined) node.append(child);
    return node;
  }

  function formatTime(iso) {
    const d = new Date(iso);
    if (isNaN(d)) return iso || "";
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function badge(text, kind = "") {
    return el("span", { class: `badge ${kind}`, text });
  }

  const severityBadge = (severity) => badge(severity, severity);

  let toastTimer;
  function toast(message, kind = "") {
    document.querySelector(".toast")?.remove();
    const node = el("div", { class: `toast ${kind}`, role: "status", text: message });
    document.body.append(node);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.remove(), 3500);
  }

  // Run fn now and every `ms`, skipping a tick if the previous one is still running.
  function poll(fn, ms) {
    let busy = false;
    const tick = async () => {
      if (busy) return;
      busy = true;
      try { await fn(); } finally { busy = false; }
    };
    tick();
    return setInterval(tick, ms);
  }

  // Top bar: is Discord alerting set up, and are the server and background activity running?
  async function updateStatusChip() {
    const set = (id, dotClass, text) => {
      const dot = document.getElementById(`${id}-dot`);
      const label = document.getElementById(`${id}-text`);
      if (dot) dot.className = `dot ${dotClass}`;
      if (label) label.textContent = text;
    };
    try {
      const stats = await api("/stats");
      set("webhook", stats.webhook_configured ? "ok" : "", stats.webhook_configured ? "Discord on" : "Discord off");
      set("status", stats.running ? "ok" : "", stats.running ? "Simulation running" : "Simulation paused");
    } catch {
      set("webhook", "", "Discord");
      set("status", "bad", "Server offline");
    }
  }
  setInterval(updateStatusChip, 4000);
  document.addEventListener("DOMContentLoaded", updateStatusChip);

  const EVENT_LABELS = {
    process_creation: "Program started",
    authentication_success: "Logon success",
    authentication_failure: "Logon failed",
    account_created: "Account created",
    network_connection: "Network connection",
  };

  function describeEvent(e) {
    switch (e.event_type) {
      case "process_creation": return e.command_line || e.process_name || "";
      case "authentication_success":
      case "authentication_failure": return e.source_ip ? `from ${e.source_ip}` : "from unknown source";
      case "account_created": return `new account: ${e.target_user || "?"}`;
      case "network_connection": {
        const mb = e.bytes_out ? `${(e.bytes_out / 1e6).toFixed(1)} MB` : "";
        return `→ ${e.dest_ip || "?"}${e.dest_port ? ":" + e.dest_port : ""} ${mb}`.trim();
      }
      default: return "";
    }
  }

  return { api, el, formatTime, badge, severityBadge, toast, poll, EVENT_LABELS, describeEvent };
})();
