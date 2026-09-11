"""
PhishGuard Agent Server
========================
Flask server that receives URLs from the Chrome extension,
analyzes them with Qwen2.5-VL (screenshot) + Qwen2.5 (URL),
and returns a threat verdict.

Usage:
    python agent_server.py

Endpoints:
    GET  /health          — liveness check
    POST /analyze         — analyze a URL {"url": "https://..."}
"""

import os, sys, io, json, time, hashlib, logging, threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, request, jsonify

import torch
from transformers import (
    Qwen2_5_VLForConditionalGeneration, AutoTokenizer,
    AutoModelForCausalLM, AutoProcessor, BitsAndBytesConfig,
)
from qwen_vl_utils import process_vision_info
from PIL import Image
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from knowledge_base import (
    TRUSTED_DOMAINS, TRUSTED_TLDS,
    ADULT_DOMAINS, GAMBLING_DOMAINS, GAMBLING_TLDS,
    CLICKUNDER_PARAMS,
    VLM_ADULT_SIGNALS, VLM_GAMBLING_SIGNALS,
    VLM_PHISHING_SIGNALS, VLM_MALWARE_SIGNALS,
    THREAT_DESCRIPTIONS,
)

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR       = Path(__file__).parent.parent
SCREENSHOT_DIR = BASE_DIR / "screenshots"
THREAT_DIR     = BASE_DIR / "threats"
LOG_DIR        = BASE_DIR / "logs"
for d in [SCREENSHOT_DIR, THREAT_DIR, LOG_DIR]: d.mkdir(exist_ok=True)

# ── Config ─────────────────────────────────────────────────────────────────────
HF_TOKEN  = os.environ.get("HF_TOKEN", "")
THRESHOLD = 0.60   # Combined threat score to trigger block

# ── Helper: trusted domain check ───────────────────────────────────────────────
def is_trusted(url):
    try:
        host = urlparse(url).hostname or ""
        for d in TRUSTED_DOMAINS:
            if host == d or host.endswith("." + d):
                return True
        for tld in TRUSTED_TLDS:
            if host.endswith(tld):
                return True
        return False
    except Exception:
        return False

# ── Helper: known adult domain check ───────────────────────────────────────────
def is_known_adult(url):
    try:
        host = urlparse(url).hostname or ""
        host = host.lower().replace("www.", "")
        # Adult domains
        if any(a in host for a in ADULT_DOMAINS):
            return True, "ADULT CONTENT"
        # Gambling domains
        if any(g in host for g in GAMBLING_DOMAINS):
            return True, "GAMBLING/SCAM"
        # Gambling TLDs
        tld = "." + host.split(".")[-1] if "." in host else ""
        if tld in GAMBLING_TLDS:
            return True, "GAMBLING/SCAM"
        # Clickunder affiliate params
        url_lower = url.lower()
        if any(p in url_lower for p in CLICKUNDER_PARAMS):
            safe_hosts = ["google", "facebook", "amazon", "microsoft"]
            if not any(s in host for s in safe_hosts):
                return True, "GAMBLING/SCAM"
        return False, None
    except Exception:
        return False, None

# ── Logging (UTF-8, fixes Windows cp1252) ─────────────────────────────────────
log = logging.getLogger("phishguard")
log.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
fh  = logging.FileHandler(LOG_DIR / "agent.log", encoding="utf-8")
sh  = logging.StreamHandler(
        io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace"))
fh.setFormatter(fmt); sh.setFormatter(fmt)
log.addHandler(fh); log.addHandler(sh)

# ── 4-bit NF4 double quantization ─────────────────────────────────────────────
bnb = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_use_double_quant=True,   # quantize quantization constants
    bnb_4bit_quant_type="nf4",        # NormalFloat4 — optimal for LLM weights
    bnb_4bit_compute_dtype=torch.bfloat16,
)

app      = Flask(__name__)
VLM = LLM = PROC = TOK = None
GPU_LOCK = threading.Lock()   # one GPU inference at a time

# ── Model loading ──────────────────────────────────────────────────────────────
def load_models():
    global VLM, PROC, LLM, TOK
    log.info("Loading VLM: Qwen2.5-VL-3B-Instruct (4-bit NF4)...")
    PROC = AutoProcessor.from_pretrained(
        "Qwen/Qwen2.5-VL-3B-Instruct", token=HF_TOKEN or None,
        min_pixels=256*28*28, max_pixels=1280*28*28,
    )
    VLM = Qwen2_5_VLForConditionalGeneration.from_pretrained(
        "Qwen/Qwen2.5-VL-3B-Instruct", token=HF_TOKEN or None,
        quantization_config=bnb, device_map="auto", dtype=torch.bfloat16,
    )
    VLM.eval()
    log.info("VLM ready. VRAM: %.2f GB", torch.cuda.memory_allocated()/1e9)

    log.info("Loading LLM: Qwen2.5-3B-Instruct (4-bit NF4)...")
    TOK = AutoTokenizer.from_pretrained(
        "Qwen/Qwen2.5-3B-Instruct", token=HF_TOKEN or None)
    LLM = AutoModelForCausalLM.from_pretrained(
        "Qwen/Qwen2.5-3B-Instruct", token=HF_TOKEN or None,
        quantization_config=bnb, device_map="auto", dtype=torch.bfloat16,
    )
    LLM.eval()
    log.info("LLM ready. Total VRAM: %.2f GB", torch.cuda.memory_allocated()/1e9)

# ── Screenshot ─────────────────────────────────────────────────────────────────
def take_screenshot(url):
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--window-size=1280,800")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_experimental_option("prefs", {"safebrowsing.enabled": False})
    driver = None
    try:
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(12)
        try: driver.get(url)
        except: pass
        time.sleep(3)
        slug = hashlib.md5(url.encode()).hexdigest()[:8]
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = SCREENSHOT_DIR / f"scan_{ts}_{slug}.png"
        driver.save_screenshot(str(path))
        return path, driver.title or ""
    finally:
        if driver: driver.quit()

# ── VLM single inference ───────────────────────────────────────────────────────
def vlm_infer(pil_img, prompt_text):
    messages = [{"role": "user", "content": [
        {"type": "image", "image": pil_img},
        {"type": "text",  "text": prompt_text},
    ]}]
    text = PROC.apply_chat_template(messages, tokenize=False,
                                    add_generation_prompt=True)
    ii, vi = process_vision_info(messages)
    inp = PROC(text=[text], images=ii, videos=vi,
               padding=True, return_tensors="pt").to("cuda")
    with torch.no_grad():
        ids = VLM.generate(**inp, max_new_tokens=512, do_sample=False)
    return PROC.batch_decode(
        [ids[0][inp.input_ids.shape[1]:]], skip_special_tokens=True)[0]

# ── VLM: two-pass visual analysis ─────────────────────────────────────────────
def run_vlm(img_path, url):
    """
    Pass 1 — READ:  extract all visible text from the screenshot (OCR-style)
    Pass 2 — JUDGE: classify threat based on extracted text + visual content
    """
    log.info("VLM Pass 1 — reading text from screenshot...")
    pil_img = Image.open(str(img_path)).convert("RGB")

    extracted = vlm_infer(pil_img,
        "Read this webpage screenshot carefully.\n"
        "Extract ALL text you can see including: headlines, titles, "
        "button text, menu items, warning messages, popup text, "
        "form labels, age verification text, urgency messages, "
        "any promotional offers.\n"
        "List everything you can read, one item per line.")

    log.info("VLM extracted text:\n%s", extracted[:600])

    # Build dynamic signal lists from knowledge base
    adult_sigs    = ", ".join(VLM_ADULT_SIGNALS[:18])
    gambling_sigs = ", ".join(VLM_GAMBLING_SIGNALS[:18])
    phish_sigs    = ", ".join(VLM_PHISHING_SIGNALS[:15])
    malware_sigs  = ", ".join(VLM_MALWARE_SIGNALS[:15])

    log.info("VLM Pass 2 — classifying threat from extracted text...")
    judge_prompt = f"""You are a cybersecurity expert. Analyze this webpage.

URL: {url}

TEXT EXTRACTED FROM THE PAGE:
{extracted[:1500]}

DECISION RULES — apply these to the extracted text:

ADULT CONTENT (threat_score=0.90): Text contains any of:
{adult_sigs}

GAMBLING/SCAM (threat_score=0.88): Text contains any of:
{gambling_sigs}
Also: betting odds, deposit bonuses, casino game thumbnails visible

PHISHING (threat_score=0.85): Text contains any of:
{phish_sigs}
Also: login form copying real brand on wrong domain

MALWARE/SCAM (threat_score=0.85): Text contains any of:
{malware_sigs}

LEGITIMATE (threat_score=0.02):
Normal company, news, tech, education, government site. No threats found.

Respond ONLY with this exact JSON (no markdown, no extra text):
{{
  "page_type": "adult_content OR gambling_scam OR phishing OR malware_scam OR legitimate",
  "threat_score": 0.0,
  "key_text_found": ["exact phrases from page that triggered decision"],
  "description": "one sentence: what is this website?",
  "signals": ["list what you found"],
  "reason": "one sentence: why this threat_score?"
}}"""

    raw = vlm_infer(pil_img, judge_prompt)
    log.info("VLM Pass 2 raw:\n%s", raw[:500])

    result = parse_json(raw)
    result["extracted_text"] = extracted[:400]
    log.info("VLM: page_type=%s threat_score=%.2f | %s",
             result.get("page_type"), result.get("threat_score", 0),
             result.get("reason", "")[:100])
    return result

# ── LLM: URL structure analysis ───────────────────────────────────────────────
def run_llm(url):
    """Analyze URL domain structure for threat patterns."""
    log.info("LLM analyzing URL: %s", url)
    try:
        parsed   = urlparse(url)
        hostname = parsed.hostname or ""
        path     = parsed.path or ""
        tld      = "." + hostname.split(".")[-1] if "." in hostname else ""
    except Exception:
        hostname = url; path = tld = ""

    prompt = f"""You are a URL security analyst. Analyze this URL structure only.

FULL URL: {url}
DOMAIN:   {hostname}
PATH:     {path[:100]}
TLD:      {tld}

Score this URL from 0.0 (safe) to 1.0 (threat) based on structure alone.

STEP 1 — Adult domain keywords in name:
porn, xxx, sex, nude, cam, escort, adult, hentai, erotic, brazzers, onlyfans,
xhamster, xvideos, xnxx, redtube, chaturbate, stripchat, camsoda, spankbang,
bangbros, porndude, toppornsites, vrporn, faphouse, tube8, slutload, beeg
→ threat_score=0.90, threat_type="adult_domain"

STEP 2 — Gambling/betting domain:
Keywords: bet, casino, poker, slots, gambling, lottery, roulette, jackpot, wager
Known platforms: 1xbet, 1xlite, melbet, betwinner, mostbet, 22bet, betway,
betfair, dafabet, parimatch, baji, baji999, jeetwin, nagad88, krikya, marvelbet,
crickex, khela88, indibet, fun88, stake, bc.game, rollbit, roobet, cloudbet,
bitstarz, babu88, six6s, lotus365, wolf777, cricbet99, gbets, mcw, live88
Number+letter pattern (babu88, nagad88, krikya99, 1xlite-08668) = gambling
→ threat_score=0.87, threat_type="gambling"

STEP 3 — Clickunder/affiliate scam URL:
Contains: stag=, btag=, affid=, aff_id=, click_id=, visit_id=, tracking_link=
Contains: []MS[], []null[], site_id_token, clickunder, popunder
Multiple encoded redirects: %2F appearing 5+ times
Random numbers in domain + unusual TLD: 1xlite-08668.world
→ threat_score=0.85, threat_type="clickunder_scam"

STEP 4 — Phishing domain patterns:
Number substitution: paypa1, g00gle, amaz0n, faceb00k, micros0ft, app1e
Brand + extra word: paypal-secure, amazon-login, google-verify
Wrong TLD for known brand: google.xyz, facebook.tk, paypal.top
→ threat_score=0.85, threat_type="phishing"

STEP 5 — Suspicious TLD with random domain:
Suspicious TLDs: .xyz .tk .top .click .cam .buzz .gq .ml .cf .pw .cc .su
Random-looking chars + suspicious TLD
→ threat_score=0.75, threat_type="malware"

STEP 6 — Safe:
Real company, known brand, education, government, news
→ threat_score=0.05, threat_type="safe"

IMPORTANT: Long URLs from google.com, amazon.com, youtube.com are ALWAYS safe.
Only flag URLs where the BASE DOMAIN itself is unknown or suspicious.

Respond ONLY with JSON (no extra text before or after):
{{
  "threat_score": 0.05,
  "threat_type": "safe",
  "is_adult_domain": false,
  "domain_flags": ["specific patterns found"],
  "reason": "one sentence"
}}"""

    inp = TOK(prompt, return_tensors="pt").to("cuda")
    with torch.no_grad():
        out = LLM.generate(**inp, max_new_tokens=250, do_sample=False,
                           pad_token_id=TOK.eos_token_id)
    raw = TOK.decode(out[0][inp.input_ids.shape[1]:], skip_special_tokens=True)
    log.info("LLM raw:\n%s", raw[:400])

    result = parse_json(raw)
    log.info("LLM: threat_type=%s threat_score=%.2f | %s",
             result.get("threat_type"), result.get("threat_score", 0),
             result.get("reason", "")[:100])
    return result

# ── Score fusion ───────────────────────────────────────────────────────────────
def combine(vlm_r, llm_r):
    """
    Fuse VLM visual score (65%) + LLM URL score (35%).
    Apply boosting rules for strong agreement or known threat types.
    """
    vs = float(vlm_r.get("threat_score", 0.0))
    ls = float(llm_r.get("threat_score", 0.0))
    vt = vlm_r.get("page_type", "legitimate")
    lt = llm_r.get("threat_type", "safe")
    llm_adult = bool(llm_r.get("is_adult_domain", False))

    # Weighted average: VLM sees the page (65%), LLM sees the URL (35%)
    combined = (vs * 0.65) + (ls * 0.35)

    # Boost: both models strongly agree it's a threat
    if vs >= 0.70 and ls >= 0.70:
        combined = min(1.0, combined * 1.2)

    # Floor: known adult domain from LLM URL analysis
    if llm_adult or lt == "adult_domain":
        combined = max(combined, 0.80)

    # Floor: VLM sees adult content on screen
    if vt == "adult_content":
        combined = max(combined, 0.80)

    # Floor: VLM sees gambling UI
    if vt == "gambling_scam":
        combined = max(combined, 0.78)

    # Floor: LLM detects gambling/clickunder domain
    if lt in ("gambling", "clickunder_scam"):
        combined = max(combined, 0.75)

    # Strong boost: both agree on gambling
    if vt == "gambling_scam" and lt in ("gambling", "clickunder_scam"):
        combined = max(combined, 0.92)

    is_threat = combined >= THRESHOLD

    # Determine threat label
    if vt == "adult_content" or llm_adult or lt == "adult_domain":
        threat_type = "ADULT CONTENT"
    elif vt == "gambling_scam" or lt in ("gambling", "clickunder_scam"):
        threat_type = "GAMBLING/SCAM"
    elif vt == "phishing" or lt == "phishing":
        threat_type = "PHISHING"
    elif vt == "malware_scam" or lt == "malware":
        threat_type = "MALWARE/SCAM"
    else:
        threat_type = "SAFE"

    return {
        "is_threat":       is_threat,
        "threat_type":     threat_type if is_threat else "SAFE",
        "combined_score":  round(combined, 3),
        "vlm_score":       round(vs, 3),
        "llm_score":       round(ls, 3),
        "vlm_page_type":   vt,
        "llm_threat_type": lt,
        "signals":         vlm_r.get("signals", []) + llm_r.get("domain_flags", []),
        "description":     vlm_r.get("description", ""),
        "key_text_found":  vlm_r.get("key_text_found", []),
        "vlm_reason":      vlm_r.get("reason", ""),
        "llm_reason":      llm_r.get("reason", ""),
    }

# ── JSON parser ────────────────────────────────────────────────────────────────
def parse_json(text):
    text = text.strip()
    for fence in ["```json", "```"]:
        text = text.replace(fence, "")
    text = text.strip()
    start = text.find("{")
    depth = 0; end = -1
    for i, c in enumerate(text[start:], start):
        if c == "{": depth += 1
        if c == "}": depth -= 1
        if depth == 0: end = i + 1; break
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except Exception as e:
            log.warning("JSON decode: %s", e)
    log.warning("JSON parse failed: %s", text[:200])
    return {
        "threat_score": 0.0, "page_type": "legitimate",
        "threat_type": "safe", "is_adult_domain": False,
        "signals": [], "domain_flags": [],
        "reason": "parse error", "description": "unknown",
        "key_text_found": [],
    }

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "models_loaded": VLM is not None})

@app.route("/analyze", methods=["POST"])
def analyze():
    url = (request.json or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "no url"}), 400

    # Fast path 1: trusted domain
    if is_trusted(url):
        log.info("TRUSTED (skip): %s", url)
        return jsonify({
            "is_threat": False, "threat_type": "SAFE",
            "combined_score": 0.0, "trusted": True,
            "vlm_reason": "Trusted domain", "llm_reason": "",
        })

    # Fast path 2: known adult/gambling domain
    flagged, fast_type = is_known_adult(url)
    if flagged:
        log.info("FAST-PATH %s: %s", fast_type, url)
        try:
            img_path, _ = take_screenshot(url)
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            slug = hashlib.md5(url.encode()).hexdigest()[:8]
            dst  = THREAT_DIR / f"threat_{ts}_{slug}.png"
            img_path.rename(dst)
        except Exception:
            pass
        return jsonify({
            "is_threat": True, "threat_type": fast_type,
            "combined_score": 0.95, "vlm_score": 0.95, "llm_score": 0.95,
            "signals": [f"Known {fast_type.lower()} domain"],
            "vlm_reason": f"Domain matched {fast_type.lower()} list",
            "llm_reason": "Domain/URL pattern in knowledge base",
        })

    log.info("=== Analyzing: %s ===", url)
    try:
        img_path, title = take_screenshot(url)
        log.info("Screenshot: %s", img_path)

        with GPU_LOCK:
            vlm_r = run_vlm(img_path, url)
            llm_r = run_llm(url)

        verdict = combine(vlm_r, llm_r)
        log.info("VERDICT: %s [%.0f%%] VLM=%.0f%% LLM=%.0f%% | %s",
                 verdict["threat_type"],
                 verdict["combined_score"] * 100,
                 verdict["vlm_score"] * 100,
                 verdict["llm_score"] * 100, url)

        if verdict["is_threat"]:
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            slug = hashlib.md5(url.encode()).hexdigest()[:8]
            name = f"threat_{ts}_{slug}"
            dst  = THREAT_DIR / f"{name}.png"
            img_path.rename(dst)
            report = {
                "timestamp": datetime.now().isoformat(),
                "url": url, "title": title,
                "verdict": verdict, "screenshot": str(dst),
            }
            (THREAT_DIR / f"{name}.json").write_text(
                json.dumps(report, indent=2, ensure_ascii=False),
                encoding="utf-8")
        else:
            img_path.unlink(missing_ok=True)

        return jsonify(verdict)

    except Exception as e:
        log.error("Analysis error: %s", e, exc_info=True)
        return jsonify({
            "is_threat": False, "threat_type": "SAFE",
            "combined_score": 0.0, "error": str(e)
        }), 200

if __name__ == "__main__":
    if not HF_TOKEN:
        log.warning("HF_TOKEN not set — models must already be downloaded locally")
    load_models()
    log.info("Agent on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, threaded=True)
