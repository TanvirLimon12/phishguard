"""
PhishGuard CLI — Manual URL Checker
=====================================
Usage:
    python phishguard.py https://suspicious-site.com
    python phishguard.py urls.txt          (batch: one URL per line)
    python phishguard.py https://... --headless
    python phishguard.py https://... --threshold 0.75
"""

import os, sys, io, json, time, hashlib, logging, argparse
from datetime import datetime
from pathlib import Path

import torch
from transformers import (
    Qwen2_5_VLForConditionalGeneration,
    AutoTokenizer, AutoModelForCausalLM,
    AutoProcessor, BitsAndBytesConfig,
)
from qwen_vl_utils import process_vision_info
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from PIL import Image

from knowledge_base import (
    TRUSTED_DOMAINS, TRUSTED_TLDS,
    ADULT_DOMAINS, GAMBLING_DOMAINS, GAMBLING_TLDS,
    CLICKUNDER_PARAMS,
    VLM_ADULT_SIGNALS, VLM_GAMBLING_SIGNALS,
    VLM_PHISHING_SIGNALS, VLM_MALWARE_SIGNALS,
)
from urllib.parse import urlparse

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR       = Path(__file__).parent.parent
SCREENSHOT_DIR = BASE_DIR / "screenshots"
THREAT_DIR     = BASE_DIR / "threats"
LOG_DIR        = BASE_DIR / "logs"
for d in [SCREENSHOT_DIR, THREAT_DIR, LOG_DIR]: d.mkdir(exist_ok=True)

HF_TOKEN         = os.environ.get("HF_TOKEN", "")
THREAT_THRESHOLD = 0.60
PAGE_LOAD_WAIT   = 3

# ── Logging ────────────────────────────────────────────────────────────────────
log = logging.getLogger("phishguard")
log.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
fh  = logging.FileHandler(LOG_DIR / "phishguard.log", encoding="utf-8")
sh  = logging.StreamHandler(
        io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace"))
fh.setFormatter(fmt); sh.setFormatter(fmt)
log.addHandler(fh); log.addHandler(sh)

# ── 4-bit NF4 quantization ─────────────────────────────────────────────────────
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
)

def is_trusted(url):
    try:
        host = urlparse(url).hostname or ""
        return (any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS)
                or any(host.endswith(t) for t in TRUSTED_TLDS))
    except Exception:
        return False

def load_models():
    log.info("=" * 55)
    log.info("Loading VLM: Qwen2.5-VL-3B-Instruct (4-bit NF4)...")
    proc = AutoProcessor.from_pretrained(
        "Qwen/Qwen2.5-VL-3B-Instruct", token=HF_TOKEN or None,
        min_pixels=256*28*28, max_pixels=1024*28*28)
    vlm  = Qwen2_5_VLForConditionalGeneration.from_pretrained(
        "Qwen/Qwen2.5-VL-3B-Instruct", token=HF_TOKEN or None,
        quantization_config=bnb_config, device_map="auto", dtype=torch.bfloat16)
    vlm.eval()
    log.info("VLM ready. VRAM: %.2f GB", torch.cuda.memory_allocated()/1e9)

    log.info("Loading LLM: Qwen2.5-3B-Instruct (4-bit NF4)...")
    tok = AutoTokenizer.from_pretrained(
        "Qwen/Qwen2.5-3B-Instruct", token=HF_TOKEN or None)
    llm = AutoModelForCausalLM.from_pretrained(
        "Qwen/Qwen2.5-3B-Instruct", token=HF_TOKEN or None,
        quantization_config=bnb_config, device_map="auto", dtype=torch.bfloat16)
    llm.eval()
    log.info("LLM ready. Total VRAM: %.2f GB", torch.cuda.memory_allocated()/1e9)
    log.info("=" * 55)
    return vlm, proc, llm, tok

def screenshot_url(url, visible=True):
    opts = Options()
    if not visible: opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox"); opts.add_argument("--window-size=1280,800")
    opts.add_argument("--disable-dev-shm-usage"); opts.add_argument("--disable-gpu")
    opts.add_experimental_option("prefs", {"safebrowsing.enabled": False})
    driver = None
    try:
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(12)
        try: driver.get(url)
        except: pass
        time.sleep(PAGE_LOAD_WAIT)
        title = driver.title or "no title"
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug  = hashlib.md5(url.encode()).hexdigest()[:8]
        ss    = str(SCREENSHOT_DIR / f"scan_{ts}_{slug}.png")
        driver.save_screenshot(ss)
        return ss, title
    finally:
        if driver: driver.quit()

def vlm_infer(vlm, proc, pil_img, prompt):
    messages = [{"role":"user","content":[
        {"type":"image","image":pil_img},
        {"type":"text","text":prompt}]}]
    text = proc.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    ii, vi = process_vision_info(messages)
    inp = proc(text=[text], images=ii, videos=vi, padding=True, return_tensors="pt").to("cuda")
    with torch.no_grad():
        ids = vlm.generate(**inp, max_new_tokens=512, do_sample=False)
    return proc.batch_decode([ids[0][inp.input_ids.shape[1]:]], skip_special_tokens=True)[0]

def run_vlm(vlm, proc, img_path, url):
    pil_img = Image.open(img_path).convert("RGB")
    extracted = vlm_infer(vlm, proc, pil_img,
        "Extract ALL text visible on this webpage screenshot: "
        "headlines, buttons, warnings, age gates, form labels. List everything.")
    log.info("Extracted text:\n%s", extracted[:500])

    adult_sigs    = ", ".join(VLM_ADULT_SIGNALS[:15])
    gambling_sigs = ", ".join(VLM_GAMBLING_SIGNALS[:15])
    phish_sigs    = ", ".join(VLM_PHISHING_SIGNALS[:12])
    malware_sigs  = ", ".join(VLM_MALWARE_SIGNALS[:12])

    raw = vlm_infer(vlm, proc, pil_img, f"""You are a cybersecurity expert.
URL: {url}
EXTRACTED TEXT: {extracted[:1200]}

Rate threat_score 0.0 (safe) to 1.0 (threat):
ADULT CONTENT (0.90): {adult_sigs}
GAMBLING (0.88): {gambling_sigs}
PHISHING (0.85): {phish_sigs}
MALWARE (0.85): {malware_sigs}
LEGITIMATE (0.02): normal website

Return ONLY JSON:
{{"page_type":"legitimate","threat_score":0.0,"description":"","signals":[],"reason":""}}""")

    result = parse_json(raw)
    log.info("VLM: %s %.2f | %s", result.get("page_type"), result.get("threat_score",0), result.get("reason","")[:80])
    return result

def run_llm(llm, tok, url):
    try:
        parsed = urlparse(url); hostname = parsed.hostname or ""; tld = "." + hostname.split(".")[-1] if "." in hostname else ""
    except: hostname = url; tld = ""
    prompt = f"""URL security analyst. Analyze: {url}
Domain: {hostname}, TLD: {tld}

adult domain keywords: porn,xxx,sex,nude,cam,escort,adult,onlyfans,brazzers,xhamster → 0.90
gambling: bet,casino,poker,1xbet,babu88,melbet,mostbet,krikya,jeetwin,stake,rollbit → 0.87
clickunder: stag=,btag=,visit_id=,tracking_link=,clickunder,popunder → 0.85
phishing: paypa1,g00gle,paypal-secure,amazon-login → 0.85
suspicious TLD: .xyz,.tk,.top,.cam,.buzz → 0.75
safe: known company, gov, edu → 0.05

Return ONLY JSON:
{{"threat_score":0.05,"threat_type":"safe","is_adult_domain":false,"domain_flags":[],"reason":""}}"""
    inp = tok(prompt, return_tensors="pt").to("cuda")
    with torch.no_grad():
        out = llm.generate(**inp, max_new_tokens=200, do_sample=False, pad_token_id=tok.eos_token_id)
    raw = tok.decode(out[0][inp.input_ids.shape[1]:], skip_special_tokens=True)
    result = parse_json(raw)
    log.info("LLM: %s %.2f | %s", result.get("threat_type"), result.get("threat_score",0), result.get("reason","")[:80])
    return result

def combine(vlm_r, llm_r):
    vs = float(vlm_r.get("threat_score", 0.0))
    ls = float(llm_r.get("threat_score", 0.0))
    vt = vlm_r.get("page_type", "legitimate")
    lt = llm_r.get("threat_type", "safe")
    combined = (vs * 0.65) + (ls * 0.35)
    if vs >= 0.70 and ls >= 0.70: combined = min(1.0, combined * 1.2)
    if lt == "adult_domain" or llm_r.get("is_adult_domain"): combined = max(combined, 0.80)
    if vt == "adult_content": combined = max(combined, 0.80)
    if vt == "gambling_scam": combined = max(combined, 0.78)
    if lt in ("gambling","clickunder_scam"): combined = max(combined, 0.75)
    if vt == "gambling_scam" and lt in ("gambling","clickunder_scam"): combined = max(combined, 0.92)
    is_threat = combined >= THREAT_THRESHOLD
    if vt == "adult_content" or lt == "adult_domain": threat_type = "ADULT CONTENT"
    elif vt == "gambling_scam" or lt in ("gambling","clickunder_scam"): threat_type = "GAMBLING/SCAM"
    elif vt == "phishing" or lt == "phishing": threat_type = "PHISHING"
    elif vt in ("malware_scam",) or lt == "malware": threat_type = "MALWARE/SCAM"
    else: threat_type = "SAFE"
    return {"is_threat":is_threat,"threat_type":threat_type if is_threat else "SAFE",
            "combined_score":round(combined,3),"vlm_score":round(vs,3),"llm_score":round(ls,3),
            "signals":vlm_r.get("signals",[]),"vlm_reason":vlm_r.get("reason",""),
            "llm_reason":llm_r.get("reason","")}

def parse_json(text):
    text = text.strip().replace("```json","").replace("```","").strip()
    start = text.find("{"); depth = 0; end = -1
    for i, c in enumerate(text[start:], start):
        if c == "{": depth += 1
        if c == "}": depth -= 1
        if depth == 0: end = i+1; break
    if start != -1 and end > start:
        try: return json.loads(text[start:end])
        except: pass
    return {"threat_score":0.0,"page_type":"legitimate","threat_type":"safe",
            "is_adult_domain":False,"signals":[],"domain_flags":[],"reason":"parse error"}

def print_report(url, title, verdict):
    pct = int(verdict["combined_score"] * 100)
    sep = "=" * 55
    print(f"\n{sep}")
    print(f"  PhishGuard Report")
    print(sep)
    print(f"  URL    : {url}")
    print(f"  Title  : {title}")
    print(f"  Score  : {pct}%  (VLM={int(verdict['vlm_score']*100)}%  LLM={int(verdict['llm_score']*100)}%)")
    print(f"  Result : {'[' + verdict['threat_type'] + '] - BLOCKED' if verdict['is_threat'] else '[SAFE]'}")
    print(sep)
    if verdict.get("signals"):
        print(f"  Signals    : {', '.join(verdict['signals'][:5])}")
    if verdict.get("vlm_reason"):
        print(f"  VLM says   : {verdict['vlm_reason']}")
    if verdict.get("llm_reason"):
        print(f"  LLM says   : {verdict['llm_reason']}")
    print(sep + "\n")

def check_url(url, vlm, proc, llm, tok, visible=True):
    if is_trusted(url):
        print(f"\n[TRUSTED] Skipping: {url}\n")
        return {"is_threat": False, "threat_type": "SAFE", "combined_score": 0.0}
    print(f"\n[*] Checking: {url}")
    ss, title = screenshot_url(url, visible=visible)
    vlm_r  = run_vlm(vlm, proc, ss, url)
    llm_r  = run_llm(llm, tok, url)
    verdict = combine(vlm_r, llm_r)
    print_report(url, title, verdict)
    if verdict["is_threat"]:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = hashlib.md5(url.encode()).hexdigest()[:8]
        name = f"threat_{ts}_{slug}"
        from pathlib import Path
        dst = THREAT_DIR / f"{name}.png"
        Path(ss).rename(dst)
        (THREAT_DIR / f"{name}.json").write_text(
            json.dumps({"url":url,"title":title,"verdict":verdict}, indent=2),
            encoding="utf-8")
        print(f"[!] Evidence saved: {THREAT_DIR / name}.json")
    else:
        Path(ss).unlink(missing_ok=True)
    return verdict

def main():
    global THREAT_THRESHOLD
    parser = argparse.ArgumentParser(description="PhishGuard CLI — AI URL checker")
    parser.add_argument("target", help="URL or .txt file with one URL per line")
    parser.add_argument("--headless",  action="store_true", help="No visible browser")
    parser.add_argument("--threshold", type=float, default=0.60, help="Block threshold (default 0.60)")
    args = parser.parse_args()
    THREAT_THRESHOLD = args.threshold

    if not HF_TOKEN:
        print("\nWARNING: HF_TOKEN not set.")
        print("PowerShell: $env:HF_TOKEN = 'hf_...'")
        print("Linux/Mac:  export HF_TOKEN=hf_...\n")

    vlm, proc, llm, tok = load_models()

    target = args.target
    if target.startswith("http://") or target.startswith("https://"):
        urls = [target]
    elif Path(target).exists():
        urls = [l.strip() for l in Path(target).read_text().splitlines()
                if l.strip().startswith("http")]
        print(f"[*] Batch: {len(urls)} URLs from {target}")
    else:
        print(f"ERROR: '{target}' is not a valid URL or file.")
        sys.exit(1)

    results = []
    for i, url in enumerate(urls, 1):
        if len(urls) > 1: print(f"\n[{i}/{len(urls)}] ----------------------------")
        try:
            v = check_url(url, vlm, proc, llm, tok, visible=not args.headless)
            results.append({"url": url, "verdict": v})
        except Exception as e:
            log.error("Failed %s: %s", url, e)
            results.append({"url": url, "error": str(e)})

    if len(urls) > 1:
        threats = [r for r in results if r.get("verdict",{}).get("is_threat")]
        print(f"\n{'='*55}")
        print(f"  BATCH SUMMARY: {len(threats)}/{len(urls)} threats detected")
        for r in results:
            v   = r.get("verdict", {})
            ico = "[THREAT]" if v.get("is_threat") else "[SAFE] "
            pct = int(v.get("combined_score", 0) * 100)
            print(f"  {ico} {pct:3d}%  {r['url']}")
        print(f"{'='*55}\n")

if __name__ == "__main__":
    main()
