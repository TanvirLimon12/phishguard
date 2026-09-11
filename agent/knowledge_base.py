"""
PhishGuard Knowledge Base
=========================
Comprehensive threat intelligence for VLM + LLM analysis.
Edit this file to add new domains, patterns, or signals.
No model retraining needed — changes take effect on next server restart.
"""

# ── TRUSTED DOMAINS (never scan, instant SAFE) ─────────────────────────────────
TRUSTED_DOMAINS = [
    # Google ecosystem
    "google.com", "googleapis.com", "gstatic.com", "google.com.bd",
    "google.co.in", "google.co.uk", "google.de", "google.fr",
    "google.co.jp", "google.com.au", "google.ca", "google.com.br",
    "gmail.com", "googlemail.com", "drive.google.com",
    "docs.google.com", "meet.google.com", "calendar.google.com",
    "play.google.com", "accounts.google.com",
    # YouTube / Video
    "youtube.com", "youtu.be", "vimeo.com", "twitch.tv",
    "dailymotion.com", "streamable.com", "loom.com",
    # Microsoft
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "office365.com", "azure.com", "bing.com", "msn.com",
    "sharepoint.com", "teams.microsoft.com", "xbox.com", "skype.com",
    # Apple
    "apple.com", "icloud.com", "itunes.apple.com",
    # Amazon
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.in",
    "amazon.co.jp", "aws.amazon.com",
    # Social Media
    "facebook.com", "fb.com", "instagram.com", "whatsapp.com",
    "messenger.com", "twitter.com", "x.com", "t.co", "threads.net",
    "reddit.com", "redd.it", "discord.com", "discord.gg",
    "telegram.org", "t.me", "snapchat.com", "pinterest.com",
    "tumblr.com", "quora.com", "linkedin.com",
    # Dev / Tech
    "github.com", "github.io", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "stackexchange.com", "superuser.com",
    "kaggle.com", "huggingface.co", "replit.com", "codepen.io",
    "jsfiddle.net", "w3schools.com", "mdn.mozilla.org",
    "npmjs.com", "pypi.org", "crates.io",
    "digitalocean.com", "linode.com", "vultr.com",
    "vercel.com", "netlify.com", "heroku.com", "render.com",
    "railway.app", "cloudflare.com", "fastly.com",
    # AI Platforms
    "claude.ai", "anthropic.com", "openai.com", "chatgpt.com",
    "deepseek.com", "perplexity.ai", "gemini.google.com",
    "copilot.microsoft.com", "midjourney.com", "stability.ai",
    "replicate.com", "cohere.com", "mistral.ai",
    # Education
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    "skillshare.com", "pluralsight.com", "brilliant.org",
    "duolingo.com", "wikipedia.org", "wikimedia.org",
    # News
    "bbc.com", "bbc.co.uk", "cnn.com", "reuters.com", "apnews.com",
    "nytimes.com", "theguardian.com", "washingtonpost.com",
    "bloomberg.com", "forbes.com", "techcrunch.com", "theverge.com",
    "wired.com", "arstechnica.com", "engadget.com", "zdnet.com",
    # Shopping
    "ebay.com", "etsy.com", "flipkart.com", "shopify.com",
    "aliexpress.com", "walmart.com", "target.com", "bestbuy.com",
    # Finance (legitimate)
    "paypal.com", "stripe.com", "square.com", "wise.com",
    "revolut.com", "coinbase.com", "binance.com", "kraken.com",
    # Productivity
    "notion.so", "figma.com", "canva.com", "slack.com", "zoom.us",
    "trello.com", "asana.com", "monday.com", "airtable.com",
    "dropbox.com", "box.com", "evernote.com",
    # Hardware brands
    "samsung.com", "sony.com", "lg.com", "hp.com", "dell.com",
    "lenovo.com", "nvidia.com", "amd.com", "intel.com",
    # International orgs
    "who.int", "un.org", "unicef.org", "worldbank.org",
    # Entertainment
    "spotify.com", "netflix.com", "hulu.com", "disneyplus.com",
    "primevideo.com", "airbnb.com", "booking.com", "expedia.com",
    "tripadvisor.com", "uber.com", "lyft.com",
]

TRUSTED_TLDS = [
    ".gov", ".gov.in", ".gov.bd", ".gov.uk", ".gov.au", ".gov.ca",
    ".edu", ".edu.bd", ".edu.in", ".ac.uk", ".ac.in", ".ac.bd",
    ".int",   # international orgs (who.int)
    ".mil",   # military
]

# ── ADULT / PORN DOMAINS ───────────────────────────────────────────────────────
ADULT_DOMAINS = [
    # Major tubes
    "pornhub", "xvideos", "xhamster", "xnxx", "redtube", "youporn",
    "tube8", "spankbang", "porntrex", "tnaflix", "porndig", "empflix",
    "drtuber", "hardsextube", "slutload", "ashemaletube", "youjizz",
    "gotporn", "cliphunter", "extremetube", "fapvid", "beeg", "hclips",
    "sunporno", "fullporner", "fapvideos", "vxxx", "eporner", "4tube",
    "fux", "fuq", "txxx", "hlips", "playvids", "leslez", "lesbosland",
    # Premium/studio
    "brazzers", "bangbros", "nubiles", "realitykings", "fakehub",
    "mofos", "teamskeet", "digitalplayground", "wicked", "vivid",
    "playboy", "penthouse", "hustler", "score", "21naturals",
    "femjoy", "met-art",
    # OnlyFans-type
    "onlyfans", "fansly", "fanvue", "unlockd", "justforfans",
    # Cam sites
    "stripchat", "chaturbate", "camsoda", "cam4", "bongacams",
    "myfreecams", "livejasmin", "jasmin", "streamate", "imlive",
    "flirt4free", "liveprivates", "cherry.tv", "jerkmate",
    "sexier", "slutroulette", "porndudecams",
    # Gay/specialty
    "xtube", "gaymaletube", "corbinfisher", "belamionline",
    # Hentai
    "nhentai", "hentaihaven", "hanime", "hentai2read", "fakku",
    # Escort/adult dating
    "adultfriendfinder", "ashleymadison", "seeking", "sugarbook",
    "fuckbook", "hookup", "fling",
    # Review/aggregator
    "theporndude", "porndude", "toppornsites", "porngeek",
    "rabbitsreviews", "vrporn", "faphouse", "pornhd", "4kporn",
]

# ── GAMBLING / BETTING DOMAINS ─────────────────────────────────────────────────
GAMBLING_DOMAINS = [
    # Major international
    "bet365", "betway", "betfair", "betsafe", "unibet", "williamhill",
    "paddypower", "ladbrokes", "coral", "skybet", "888sport",
    "draftkings", "fanduel", "pointsbet", "caesars", "mgm",
    # Crypto gambling
    "stake", "bc.game", "rollbit", "roobet", "cloudbet", "bitcasino",
    "fortunejack", "mbitcasino", "bspin", "bitstarz", "katsubet",
    "casinoin", "vegascasino", "spinz", "slottica", "vave", "metaspins",
    # South Asian / BD / IN (illegal in many countries)
    "1xbet", "1xlite", "melbet", "betwinner", "mostbet", "22bet",
    "parimatch", "babu88", "nagad88", "krikya", "jeetwin", "baji",
    "dafabet", "marvelbet", "baji999", "betjili", "mcw", "mcasino",
    "crickex", "khela88", "mostabet", "betway88", "nine.casino",
    "six6s", "lotus365", "fun88", "d247", "b9casino", "live88",
    "cricbet99", "wolf777", "indibet", "gbets", "fairplay",
    "betbarter", "playinexch", "fairexch", "tigerexch",
    # Casino brands
    "betsson", "leovegas", "casumo", "rizk", "dunder", "kaboo",
    "thrills", "guts", "videoslots", "slotsmillion", "wildz",
    "playluck", "spinit", "jackpotcity", "royalvegas", "spinpalace",
    # Lottery
    "lottoland", "lotto24", "thelotter", "wintrillions",
]

GAMBLING_TLDS = [
    ".bet", ".casino", ".poker", ".lotto", ".win",
    ".games", ".bingo",
]

# ── PHISHING DOMAIN PATTERNS ───────────────────────────────────────────────────
PHISHING_KEYWORDS_IN_DOMAIN = [
    # Brand + extra word
    "paypal-", "amazon-", "google-", "facebook-", "microsoft-",
    "apple-", "netflix-", "bank-", "secure-", "login-", "verify-",
    "account-", "update-", "-paypal", "-amazon", "-google",
    "-facebook", "-microsoft", "-apple", "-secure", "-login",
    "-verify", "-account", "-update", "-support",
    # Number substitution (typosquatting)
    "paypa1", "g00gle", "amaz0n", "faceb00k", "micros0ft",
    "app1e", "netfl1x", "tw1tter", "1nstagram", "y0utube",
    "l1nkedin",
]

# ── SUSPICIOUS TLDs ────────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".top", ".click", ".cam", ".buzz", ".gq", ".ml",
    ".cf", ".pw", ".cc", ".su", ".kim", ".party", ".trade",
    ".science", ".work", ".review", ".country", ".stream", ".gdn",
    ".men", ".accountant", ".loan", ".download", ".racing",
    ".cricket", ".faith", ".date", ".bid",
]

# ── CLICKUNDER / AFFILIATE SCAM URL PATTERNS ──────────────────────────────────
CLICKUNDER_PARAMS = [
    "[]ms[]", "[]null[]", "{site_id}", "[site_id]", "clickunder",
    "click_id=", "visit_id=", "tracking_link=", "stag=", "btag=",
    "affid=", "aff_id=", "affiliate_id=", "ref_id=", "subid=",
    "popunder", "popads", "trafficjunky", "exoclick", "juicyads",
    "trafficfactory", "adsterra", "propellerads",
]

# ── VLM VISUAL THREAT SIGNALS ──────────────────────────────────────────────────
VLM_ADULT_SIGNALS = [
    "18+", "18 years", "adults only", "adult content",
    "adult entertainment", "explicit content", "explicit material",
    "nudity", "sexual content", "pornographic", "xxx", "erotic",
    "nsfw", "I am over 18", "I am 18", "enter if adult",
    "age verification", "age gate", "confirm your age",
    "you must be 18", "cam site", "live sex", "watch live",
    "live stream adult", "join free - adults",
]

VLM_GAMBLING_SIGNALS = [
    # Betting UI
    "bet slip", "place bet", "live betting", "sports betting",
    "in-play", "cash out", "my bets", "open bets", "bet now",
    "quick bet", "accumulator", "odds",
    # Promotions
    "100% bonus", "welcome bonus", "deposit bonus", "free bet",
    "free spins", "no deposit bonus", "reload bonus", "cashback",
    "first deposit", "100% match", "200% bonus", "500% bonus",
    "vip bonus", "loyalty points", "wagering requirement",
    # Casino games
    "crash game", "slot machine", "roulette", "blackjack",
    "baccarat", "poker room", "live casino", "live dealer",
    "jackpot", "spin to win", "provably fair", "rtp",
    # Platform names
    "1xbet", "1xgames", "babu88", "melbet", "mostbet", "betway",
    "stake.com", "bc.game", "rollbit", "krikya", "baji",
    # Registration CTAs on gambling sites
    "register now", "join now", "sign up and get",
    "deposit to play", "withdraw winnings",
]

VLM_PHISHING_SIGNALS = [
    # Account threats
    "verify your account", "confirm your identity",
    "update your information", "your account will be suspended",
    "account suspended", "account locked",
    "unusual activity detected", "suspicious login",
    "security alert", "click here immediately",
    "action required", "urgent",
    # Payment
    "update payment method", "payment failed", "billing error",
    "enter credit card", "confirm credit card", "card details",
    # Login impersonation
    "sign in with google", "continue with facebook",
    "login with apple",
    # Brand impersonation cues
    "your amazon order", "your paypal account",
    "your netflix subscription", "your apple id",
    "your microsoft account", "your google account",
    "dear customer", "dear user", "dear valued member",
]

VLM_MALWARE_SIGNALS = [
    # Fake virus alerts
    "your computer is infected", "virus detected", "malware found",
    "your device is at risk", "security threat detected",
    "call microsoft", "call apple support", "call our technician",
    "1-800", "toll free support",
    # Fake downloads
    "download now to continue", "update required",
    "plugin required", "flash player update",
    "java update required", "codec required",
    # Lottery scams
    "you have won", "congratulations you won", "claim your prize",
    "you are selected", "lucky winner", "collect your reward",
    "$1000 gift card", "iphone winner", "amazon gift card",
]

# ── URL THREAT SCORE WEIGHTS ───────────────────────────────────────────────────
URL_THREAT_WEIGHTS = {
    "known_adult_domain":      0.95,
    "known_gambling_domain":   0.90,
    "clickunder_params":       0.85,
    "gambling_tld":            0.85,
    "phishing_domain_pattern": 0.85,
    "suspicious_tld_random":   0.75,
    "suspicious_tld_only":     0.50,
    "long_url_unknown_domain": 0.70,
}

# ── THREAT DESCRIPTIONS (for reports) ─────────────────────────────────────────
THREAT_DESCRIPTIONS = {
    "ADULT CONTENT":  "This page contains adult/pornographic content",
    "GAMBLING/SCAM":  "This is a gambling/betting site — may be illegal or predatory",
    "PHISHING":       "This page impersonates a legitimate service to steal credentials",
    "MALWARE/SCAM":   "This page contains malware, fake alerts, or prize scams",
    "CLICKUNDER":     "This URL uses clickunder/affiliate tracking — likely a scam redirect",
    "SAFE":           "This page appears legitimate",
}
