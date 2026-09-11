/**
 * PhishGuard AI — Chrome Extension Background Service Worker
 * ===========================================================
 * Manifest V3 service worker that:
 *  - Intercepts every tab navigation
 *  - Maintains a serial scan queue (one at a time, no GPU oversubscription)
 *  - Sends URL to local agent_server.py for AI analysis
 *  - Injects warning banner + auto-closes threat tabs
 *  - Caches safe results (30min TTL) to avoid re-scanning
 */

const AGENT = "http://127.0.0.1:5000";

// ── Whitelist: never scan these domains ────────────────────────────────────────
const WHITELIST = [
  "google.com","googleapis.com","gstatic.com","google.com.bd","google.co.in",
  "youtube.com","youtu.be","github.com","microsoft.com","live.com","office.com",
  "stackoverflow.com","wikipedia.org","kaggle.com","huggingface.co","w3schools.com",
  "amazon.com","ebay.com","flipkart.com","facebook.com","twitter.com","x.com",
  "linkedin.com","instagram.com","reddit.com","discord.com","tiktok.com",
  "mozilla.org","apple.com","cloudflare.com","bing.com","yahoo.com","duckduckgo.com",
  "claude.ai","anthropic.com","openai.com","chatgpt.com","deepseek.com",
  "notion.so","figma.com","canva.com","vercel.com","netlify.com","twitch.tv",
  "spotify.com","netflix.com","samsung.com","who.int","cnn.com","bbc.com",
  "chrome://","chrome-extension://","about:","newtab","extensions",
  "127.0.0.1","localhost",
];

// ── State ──────────────────────────────────────────────────────────────────────
let ENABLED  = true;
let queue    = [];          // [{tabId, url}] — waiting to be scanned
let scanning = false;       // is a scan running right now?
let inFlight = new Set();   // urls currently in queue OR scanning
let cache    = new Map();   // url → {time, is_threat, verdict}
let closers  = new Map();   // tabId → close setTimeout handle

// ── Init ───────────────────────────────────────────────────────────────────────
chrome.storage.local.get("enabled", d => { ENABLED = d.enabled !== false; });
chrome.runtime.onInstalled.addListener(() => setTimeout(enqueueAllOpenTabs, 3000));
chrome.runtime.onStartup.addListener(()    => setTimeout(enqueueAllOpenTabs, 3000));

// ── Tab events ─────────────────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!ENABLED || changeInfo.status !== "complete") return;
  enqueue(tabId, tab.url || "");
});

// ── Messages from popup & injected banner ──────────────────────────────────────
chrome.runtime.onMessage.addListener(msg => {
  if (msg.type === "SET_ENABLED") {
    ENABLED = msg.value;
    chrome.storage.local.set({ enabled: ENABLED });
    if (ENABLED) enqueueAllOpenTabs();
  }

  if (msg.type === "CANCEL_CLOSE") {
    const h = closers.get(msg.tabId);
    if (h) {
      clearTimeout(h);
      closers.delete(msg.tabId);
      console.log("[PG] Cancel — keeping tab", msg.tabId);
      try {
        chrome.action.setBadgeText({ text: "SKIP", tabId: msg.tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#E67E22", tabId: msg.tabId });
        setTimeout(() => setBadge(msg.tabId, "", ""), 5000);
      } catch {}
    }
  }
});

// ── Scan all currently open tabs ───────────────────────────────────────────────
function enqueueAllOpenTabs() {
  if (!ENABLED) return;
  chrome.tabs.query({}, tabs => {
    for (const t of tabs) enqueue(t.id, t.url || "");
  });
}

// ── Enqueue a URL ──────────────────────────────────────────────────────────────
function enqueue(tabId, url) {
  if (!shouldScan(url))   return;
  if (inFlight.has(url))  return;   // already queued or scanning
  if (isCachedSafe(url))  return;   // recently confirmed safe

  inFlight.add(url);
  queue.push({ tabId, url });
  console.log(`[PG] Queued: ${url}  (queue=${queue.length})`);
  drain();
}

// ── Drain queue — ONE scan at a time ──────────────────────────────────────────
function drain() {
  if (scanning || queue.length === 0) return;
  const item = queue.shift();
  scanning = true;
  doScan(item.tabId, item.url)
    .catch(e => console.error("[PG] Scan threw:", e))
    .finally(() => {
      scanning = false;
      setTimeout(drain, 300);   // small gap between scans
    });
}

// ── Core scan ──────────────────────────────────────────────────────────────────
async function doScan(tabId, url) {
  // Verify tab still exists before spending GPU time
  const tab = await getTab(tabId);
  if (!tab) {
    console.log(`[PG] Tab ${tabId} gone before scan`);
    inFlight.delete(url);
    return;
  }

  console.log(`[PG] Scanning tab ${tabId}: ${url}`);
  setBadge(tabId, "...", "#888888");

  let verdict;
  try {
    // Health check
    const h = await fetch(`${AGENT}/health`, { signal: AbortSignal.timeout(4000) });
    if (!h.ok) throw new Error("Agent offline");

    // Analyze — long timeout because AI inference takes 1–3 minutes
    const r = await fetch(`${AGENT}/analyze`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
      signal:  AbortSignal.timeout(300000),   // 5 min
    });
    verdict = await r.json();

  } catch (err) {
    console.warn(`[PG] Request failed for ${url}:`, err.message);
    setBadge(tabId, "ERR", "#555555");
    setTimeout(() => setBadge(tabId, "", ""), 5000);
    inFlight.delete(url);
    return;
  }

  // Cache result
  const isT = !!verdict.is_threat;
  cache.set(url, { time: Date.now(), is_threat: isT, verdict });
  inFlight.delete(url);

  const pct  = Math.round((verdict.combined_score || 0) * 100);
  const type = verdict.threat_type || "THREAT";
  appendLog({ url, verdict, timestamp: Date.now() });
  console.log(`[PG] ${isT ? type : "SAFE"} ${pct}% tab=${tabId}`);

  if (isT) {
    setBadge(tabId, "BLOCK", "#CC0000");
    const icon = type === "ADULT CONTENT"  ? "🔞"
               : type === "GAMBLING/SCAM"  ? "🎰"
               : type === "MALWARE/SCAM"   ? "☠️"
               : "🛑";

    // Desktop notification
    chrome.notifications.create(`pg_${Date.now()}`, {
      type: "basic", iconUrl: "icons/icon.png",
      title: `PhishGuard: ${type} BLOCKED`,
      message: `${pct}% score\n${url.slice(0, 100)}`,
    });

    // Inject warning banner with countdown + cancel button
    chrome.scripting.executeScript({
      target: { tabId },
      func: injectBanner,
      args:  [pct, verdict.vlm_reason || "", tabId, type, icon],
    }).catch(e => console.warn("[PG] Banner failed:", e.message));

    // Schedule tab close in 5s — cancel button can stop this
    console.log(`[PG] Scheduling close in 5s for tab ${tabId}`);
    const h = setTimeout(() => {
      closers.delete(tabId);
      forceCloseTab(tabId);
    }, 5000);
    closers.set(tabId, h);

  } else {
    setBadge(tabId, "OK", "#1D9E75");
    setTimeout(() => setBadge(tabId, "", ""), 3000);
  }
}

// ── Force close a tab ──────────────────────────────────────────────────────────
function forceCloseTab(tabId) {
  chrome.tabs.get(tabId, tab => {
    if (chrome.runtime.lastError) {
      console.log(`[PG] Tab ${tabId} already gone`);
      return;
    }
    chrome.tabs.remove(tabId, () => {
      if (chrome.runtime.lastError) {
        console.warn(`[PG] remove() failed: ${chrome.runtime.lastError.message}`);
        // Last resort: inject window.close() into the page
        chrome.scripting.executeScript({
          target: { tabId },
          func: () => window.close(),
        }).catch(() => {});
      } else {
        console.log(`[PG] Tab ${tabId} closed`);
      }
    });
  });
}

// ── Warning banner injected into threat pages ──────────────────────────────────
function injectBanner(score, reason, tid, ttype, icon) {
  if (document.getElementById("pg-banner")) return;
  window._pgTabId     = tid;
  window._pgCancelled = false;

  const b = document.createElement("div");
  b.id = "pg-banner";
  b.style.cssText = [
    "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
    "background:#8B0000", "color:#fff",
    "font-family:system-ui,-apple-system,sans-serif",
    "padding:14px 20px", "display:flex", "align-items:center", "gap:14px",
    "box-shadow:0 4px 24px rgba(0,0,0,.8)", "font-size:14px",
  ].join(";");

  b.innerHTML = `
    <span style="font-size:26px">${icon}</span>
    <span style="flex:1">
      <strong style="font-size:15px">PhishGuard: ${ttype} BLOCKED (${score}%)</strong><br>
      <span style="color:#ffcccc;font-size:12px">${reason || ""}</span>
    </span>
    <span id="pg-cd" style="background:rgba(0,0,0,.4);padding:6px 14px;
      border-radius:6px;margin-right:8px;font-size:13px">
      Closing in <b id="pg-n">5</b>s
    </span>
    <button id="pg-cancel" style="background:#fff;color:#8B0000;border:none;
      padding:9px 22px;border-radius:6px;cursor:pointer;
      font-weight:700;font-size:14px">
      CANCEL
    </button>`;
  document.body.prepend(b);

  // Countdown
  let n = 5;
  const tick = setInterval(() => {
    n--;
    const el = document.getElementById("pg-n");
    if (el) el.textContent = n;
    if (n <= 0) clearInterval(tick);
  }, 1000);

  // Cancel button
  document.getElementById("pg-cancel").onclick = () => {
    clearInterval(tick);
    window._pgCancelled = true;
    b.style.background = "#1a6e3c";
    b.innerHTML = "<span style='font-size:22px'>✅</span>&nbsp;<strong>Cancelled — tab kept open.</strong>";
    chrome.runtime.sendMessage({ type: "CANCEL_CLOSE", tabId: window._pgTabId });
    setTimeout(() => b.remove(), 3000);
  };

  // window.close() fallback at 5.5s if not cancelled
  setTimeout(() => {
    if (!window._pgCancelled) window.close();
  }, 5500);
}

// ── Helpers ────────────────────────────────────────────────────────────────────
function shouldScan(url) {
  if (!url || !url.startsWith("http")) return false;
  return !WHITELIST.some(w => url.includes(w));
}

function isCachedSafe(url) {
  const c = cache.get(url);
  if (!c) return false;
  if (c.is_threat) return false;                        // always re-check threats
  return Date.now() - c.time < 30 * 60 * 1000;         // 30min for safe URLs
}

function getTab(tabId) {
  return new Promise(resolve => {
    chrome.tabs.get(tabId, tab => {
      resolve(chrome.runtime.lastError ? null : tab);
    });
  });
}

function setBadge(tabId, text, color) {
  try {
    chrome.action.setBadgeText({ text, tabId });
    if (color) chrome.action.setBadgeBackgroundColor({ color, tabId });
  } catch {}
}

function appendLog(entry) {
  chrome.storage.local.get("pglog", d => {
    const log = (d.pglog || []);
    log.unshift(entry);
    if (log.length > 100) log.splice(100);
    chrome.storage.local.set({ pglog: log });
  });
}
