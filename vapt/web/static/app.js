(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const SEV = ["critical", "high", "medium", "low", "info"];
  const RANK = Object.fromEntries(SEV.map((s, i) => [s, i]));
  const LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  const COVERS = [
    ["Injection", "Reflected XSS, error and boolean SQL injection"],
    ["Access control", "Open redirects, path traversal, missing CSRF tokens"],
    ["Misconfiguration", "Security headers, cookies, CORS, risky HTTP methods"],
    ["Exposure", "Leaked .git and .env files, backups, stack traces"],
    ["Transport", "Missing HTTPS, certificate problems, legacy TLS"],
  ];

  let meta = null, current = null, poll = null, filterSev = null, query = "";

  const el = (tag, props = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k === "style") n.style.cssText = v; // CSSOM write: allowed under the strict CSP, unlike a style attribute
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) n.setAttribute(k, v === true ? "" : v);
    }
    n.append(...kids.flat().filter((x) => x != null));
    return n;
  };
  const api = async (path, opts) => {
    const r = await fetch(path, opts);
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || `Request failed (${r.status})`);
    return data;
  };
  const isLocal = (url) => {
    try {
      const h = new URL(/^\w+:\/\//.test(url) ? url : "http://" + url).hostname;
      return h === "localhost" || h === "::1" || h === "[::1]" || /^127\./.test(h) || /^10\./.test(h) ||
        /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) || /^169\.254\./.test(h);
    } catch { return true; }
  };
  const ago = (t) => {
    const s = Math.max(0, Date.now() / 1000 - t);
    return s < 60 ? "just now" : s < 3600 ? `${Math.floor(s / 60)} min ago` : `${Math.floor(s / 3600)} h ago`;
  };
  const show = (name) => {
    for (const v of ["empty", "run", "error", "done"]) $("view-" + v).hidden = v !== name;
  };

  /* ---------- setup ---------- */
  async function init() {
    meta = await api("/api/meta");
    $("ver").textContent = "v" + meta.version;
    $("checks").append(...meta.checks.map((c) => el("label", { title: c.description },
      el("input", { type: "checkbox", value: c.name, checked: true }), el("span", { text: c.name }))));
    $("covers").append(...COVERS.map(([t, d]) => el("div", {}, el("dt", { text: t }), el("dd", { text: d }))));
    $("target").addEventListener("input", syncScope);
    $("scan-form").addEventListener("submit", start);
    $("use-lab").addEventListener("click", () => { $("target").value = "http://127.0.0.1:5000"; syncScope(); $("target").focus(); });
    $("q").addEventListener("input", (e) => { query = e.target.value.toLowerCase(); renderFindings(); });
    await refreshHistory();
    const id = location.hash.slice(1);
    if (id) open(id);
  }

  function syncScope() {
    const v = $("target").value.trim();
    const remote = v && !isLocal(v);
    $("authz-row").hidden = !remote;
    const hint = $("target-hint");
    hint.classList.toggle("warn", !!remote);
    hint.textContent = remote
      ? "This is not a private address. Confirm you are allowed to test it."
      : "Private and loopback addresses can be scanned directly.";
  }

  /* ---------- start / poll ---------- */
  async function start(e) {
    e.preventDefault();
    const err = $("form-error");
    err.hidden = true;
    const target = $("target").value.trim();
    if (!target) return fail("Enter the URL of the application to scan.");
    const checks = [...document.querySelectorAll("#checks input:checked")].map((i) => i.value);
    if (!checks.length) return fail("Select at least one check.");
    if (!isLocal(target) && !$("authorized").checked) return fail("Confirm you have permission to test this target.");
    const body = {
      target, checks, authorized: $("authorized").checked,
      max_pages: +$("max_pages").value, max_depth: +$("max_depth").value,
      max_requests: +$("max_requests").value, delay: +$("delay").value,
      cookie: $("cookie").value, test_post: $("test_post").checked, insecure: $("insecure").checked,
    };
    $("go").disabled = true;
    try {
      const job = await api("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      await open(job.id);
      refreshHistory();
    } catch (x) { fail(x.message); } finally { $("go").disabled = false; }
  }
  function fail(msg) { const e = $("form-error"); e.textContent = msg; e.hidden = false; }

  async function open(id) {
    clearTimeout(poll);
    current = id;
    history.replaceState(null, "", "#" + id);
    filterSev = null; query = ""; $("q").value = "";
    await tick();
  }

  async function tick() {
    let job;
    try { job = await api("/api/scans/" + current); }
    catch (x) { show("error"); $("err-msg").textContent = x.message; return; }
    render(job);
    if (job.status === "done" || job.status === "error") { refreshHistory(); return; }
    poll = setTimeout(tick, 600);
  }

  /* ---------- views ---------- */
  function render(job) {
    if (job.status === "error") {
      show("error"); $("err-msg").textContent = job.error; return;
    }
    if (job.status !== "done") return renderRun(job);
    show("done");
    const r = job.result;
    $("done-target").textContent = job.target;
    const n = r.findings.length;
    $("done-title").textContent = n === 0 ? "No findings" : `${n} finding${n === 1 ? "" : "s"}`;
    $("stats").textContent = `${r.pages} pages crawled, ${r.points} parameters tested, ${r.requests} requests in ${r.duration} s`;
    $("downloads").replaceChildren(...[["html", "HTML"], ["md", "Markdown"], ["json", "JSON"], ["sarif", "SARIF"]]
      .map(([f, l]) => el("a", { href: `/api/scans/${job.id}/report.${f}`, download: "", text: l })));
    window.__result = r;
    renderStrip(r);
    renderFindings();
  }

  function renderRun(job) {
    show("run");
    $("run-target").textContent = job.target;
    $("run-title").textContent = job.status === "crawling" || job.status === "queued" ? "Crawling the site" : "Running checks";
    const done = new Set(job.completed);
    $("steps").replaceChildren(...job.checks.map((c) =>
      el("li", { class: done.has(c) ? "ok" : c === job.current ? "on" : "", text: c })));
    const pct = job.status === "crawling" || job.status === "queued" ? 4 : 8 + (done.size / job.checks.length) * 92;
    $("meter-bar").style.width = pct + "%";
  }

  function renderStrip(r) {
    const counts = Object.fromEntries(SEV.map((s) => [s, 0]));
    r.findings.forEach((f) => counts[f.severity]++);
    const strip = $("strip");
    if (!r.findings.length) strip.replaceChildren(el("div", { class: "none", text: "Nothing found by the checks that ran." }));
    else strip.replaceChildren(...r.findings.map((f, i) => el("a", {
      href: "#f" + i, role: "listitem", style: `--c:var(--${f.severity})`,
      title: `${LABEL[f.severity]}: ${f.title}`, "aria-label": `${LABEL[f.severity]}: ${f.title}`,
      onclick: (e) => { e.preventDefault(); focusFinding(i); },
    })));
    $("legend").replaceChildren(...SEV.map((s) => el("button", {
      type: "button", class: counts[s] ? "" : "zero", style: `--c:var(--${s})`, "aria-pressed": filterSev === s,
      onclick: () => { filterSev = filterSev === s ? null : s; renderStrip(r); renderFindings(); },
    }, el("b", { text: counts[s] }), LABEL[s])));
  }

  function renderFindings() {
    const r = window.__result; if (!r) return;
    const rows = r.findings.map((f, i) => [f, i]).filter(([f]) =>
      (!filterSev || f.severity === filterSev) &&
      (!query || [f.title, f.url, f.parameter, f.cwe, f.owasp, f.id].join(" ").toLowerCase().includes(query)));
    rows.sort((a, b) => RANK[a[0].severity] - RANK[b[0].severity] || a[1] - b[1]);
    const box = $("findings");
    if (!rows.length) {
      box.replaceChildren(el("p", { class: "none-msg", text: r.findings.length ? "No findings match this filter." : "Every enabled check passed." }));
      return;
    }
    box.replaceChildren(...rows.map(([f, i]) => finding(f, i)));
  }

  function finding(f, i) {
    const where = f.url + (f.parameter ? `  (parameter: ${f.parameter})` : "");
    const tags = [f.id, f.cwe, f.owasp].filter(Boolean);
    return el("details", { class: "f", id: "f" + i, style: `--c:var(--${f.severity})` },
      el("summary", {},
        el("span", { class: "f-title", text: f.title }),
        el("span", { class: "f-sev", text: LABEL[f.severity] }),
        el("span", { class: "f-where", text: where })),
      el("div", { class: "f-body" },
        el("p", { text: f.description }),
        f.evidence ? [el("h3", { text: "Evidence" }), el("pre", { text: f.evidence })] : null,
        el("h3", { text: "How to fix it" }),
        el("p", { text: f.remediation }),
        el("div", { class: "tags" }, tags.map((t) => el("span", { text: t })))));
  }

  function focusFinding(i) {
    if (filterSev || query) { filterSev = null; query = ""; $("q").value = ""; renderStrip(window.__result); renderFindings(); }
    const d = $("f" + i);
    if (!d) return;
    d.open = true;
    d.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion:reduce)").matches ? "auto" : "smooth", block: "center" });
    d.classList.remove("flash"); void d.offsetWidth; d.classList.add("flash");
    d.querySelector("summary").focus({ preventScroll: true });
  }

  async function refreshHistory() {
    let list = [];
    try { list = await api("/api/scans"); } catch { return; }
    const ul = $("history");
    if (!list.length) return;
    ul.replaceChildren(...list.map((j) => {
      const s = j.summary;
      const badge = j.status === "done" ? `${Object.values(s).reduce((a, b) => a + b, 0)} found`
        : j.status === "error" ? "failed" : "running";
      return el("li", {}, el("button", { type: "button", "aria-current": j.id === current, onclick: () => open(j.id) },
        el("span", { class: "h-target", text: j.target.replace(/^https?:\/\//, "") }),
        el("span", { class: "h-badge", text: badge }),
        el("span", { class: "h-meta", text: ago(j.created) })));
    }));
  }

  init().catch((e) => { show("error"); $("err-msg").textContent = e.message; });
})();
