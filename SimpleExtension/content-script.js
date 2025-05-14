// content-script.js - Fully Optimized Phishing Detection Extension
(() => {
  ("use strict");

  let predictSplit;
  async function ensureModel() {
    if (!predictSplit) {
      // must be declared web_accessible in manifest
      const mod = await import(chrome.runtime.getURL("phish_model.js"));
      predictSplit = mod.predictSplit;
    }
  }

  // --- Global Config ---
  // const url = window.location.href;
  const url = window.location.href;
  const { hostname, pathname } = new URL(url);

  const parsed = new URL(url);
  // const hostname = window.location.hostname;
  const domain = hostname.split(".").slice(-2).join(".");
  const path = parsed.pathname || "/";

  // 1. tldextract equivalent
  // We can parse suffix+domain via URL + a small regex:
  // split hostname into labels:
  const labels = hostname.split(".");
  // suffix = last label, domain = second to last, subdomain = rest
  const suffix = labels.pop(); // "org"
  const domainLabel = labels.pop(); // "openstreetmap"
  const subdomainLabel = labels.join("."); // "wiki"

  // 2. Rebuild pathArg exactly like Python:
  const afterSuffix = url.slice(url.indexOf(suffix));
  // afterSuffix starts at "org/…"
  const slashIndex = afterSuffix.indexOf("/");
  const pathArg =
    slashIndex >= 0
      ? afterSuffix.slice(slashIndex + 1) // "wiki/Databases_and_data_access_APIs"
      : "";

  // Common lists
  const nullFormats = new Set([
    "",
    "#",
    "#nothing",
    "#doesnotexist",
    "#null",
    "#void",
    "#whatever",
    "#content",
    "javascript:void(0)",
    "javascript:void(0);",
    "javascript:;",
    "javascript",
  ]);
  const SHORTENER_REGEX =
    /bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net/;
  const suspTLDs = new Set([
    "fit",
    "tk",
    "gp",
    "ga",
    "work",
    "ml",
    "date",
    "wang",
    "men",
    "icu",
    "online",
    "click",
    "country",
    "stream",
    "download",
    "xin",
    "racing",
    "jetzt",
    "ren",
    "mom",
    "party",
    "review",
    "trade",
    "accountants",
    "science",
    "work",
    "ninja",
    "xyz",
    "faith",
    "zip",
    "cricket",
    "win",
    "accountant",
    "realtor",
    "top",
    "christmas",
    "gdn",
    "link",
    "asia",
    "club",
    "la",
    "ae",
    "exposed",
    "pe",
    "go.id",
    "rs",
    "k12.pa.us",
    "or.kr",
    "ce.ke",
    "audio",
    "gob.pe",
    "gov.az",
    "website",
    "bj",
    "mx",
    "media",
    "sa.gov.au",
  ]);
  const hints = [
    "wp",
    "login",
    "includes",
    "admin",
    "content",
    "site",
    "images",
    "js",
    "alibaba",
    "css",
    "myaccount",
    "dropbox",
    "themes",
    "plugins",
    "signin",
    "view",
  ];
  const BRANDS = [
    "accenture",
    "activisionblizzard",
    "adidas",
    "adobe",
    "adultfriendfinder",
    "agriculturalbankofchina",
    "akamai",
    "alibaba",
    "aliexpress",
    "alipay",
    "alliance",
    "alliancedata",
    "allianceone",
    "allianz",
    "alphabet",
    "amazon",
    "americanairlines",
    "americanexpress",
    "americantower",
    "amex",
    "amlint",
    "android",
    "ansys",
    "aol",
    "apple",
    "aramex",
    "asahi",
    "asus",
    "atlassian",
    "att",
    "audi",
    "autodesk",
    "autoanything",
    "avast",
    "aviva",
    "aws",
    "axa",
    "baidu",
    "bankofamerica",
    "barclays",
    "barnesandnoble",
    "baomoi",
    "bbc",
    "bbciplayer",
    "bbt",
    "bdept",
    "beats",
    "bestbuy",
    "bestwestern",
    "bga",
    "bigcommerce",
    "bigpond",
    "bitbucket",
    "bitly",
    "blackberry",
    "blindzz",
    "blogger",
    "bluehost",
    "bmo",
    "bnp",
    "bof",
    "booking",
    "bosch",
    "box",
    "bp",
    "bpi",
    "bradesco",
    "brightsource",
    "brookfield",
    "bsnl",
    "bt",
    "btconnect",
    "btopenworld",
    "budurl",
    "btinternet",
    "businessweek",
    "cafepress",
    "canada",
    "canterbury",
    "capitalone",
    "carrefour",
    "carrier",
    "cartier",
    "cba",
    "cbn",
    "cbs",
    "celcom",
    "cern",
    "chase",
    "cheddargenerator",
    "chevron",
    "chipotle",
    "christianlouboutin",
    "cigna",
    "cisco",
    "citibank",
    "citigroup",
    "citi",
    "city",
    "ckan",
    "cleartrip",
    "clickbank",
    "cloudflare",
    "clubcard",
    "cnet",
    "cocacola",
    "coca-cola",
    "cobalt",
    "commerzbank",
    "comcast",
    "commbank",
    "comparison",
    "concur",
    "congrats",
    "convenience",
    "cookiedomain",
    "co-op",
    "corsair",
    "costco",
    "coupang",
    "covid",
    "cpl",
    "creditone",
    "crm",
    "crowdflower",
    "crunchbase",
    "css",
    "cssanimation",
    "cstld",
    "cuisine",
    "cybrml",
    "dailymotion",
    "dell",
    "deloitte",
    "delta",
    "dhl",
    "diamond",
    "digitalocean",
    "dnb",
    "doe",
    "domainparking",
    "dominos",
    "douban",
    "drip",
    "drupal",
    "dtu",
    "duckduckgo",
    "dunkin",
    "dupont",
    "easymail",
    "ebay",
    "ec2",
    "ecard",
    "ecolaunch",
    "edge",
    "edible",
    "eharmony",
    "ellesmere",
    "eltax",
    "ember",
    "empire",
    "endurance",
    "enterprise",
    "episerver",
    "ericsson",
    "etsy",
    "europa",
    "evernote",
    "ewallet",
    "exxonmobil",
    "ey",
    "f5",
    "facebook",
    "fairprice",
    "fanta",
    "farmers",
    "fedex",
    "federalreserve",
    "ferrari",
    "fidelity",
    "figma",
    "fink",
    "firefox",
    "firmwork",
    "firstdata",
    "firstenergy",
    "fitbit",
    "flights",
    "flickr",
    "flipkart",
    "fluss",
    "fly",
    "foodpanda",
    "ford",
    "fortune",
    "forum",
    "foursquare",
    "frappr",
    "freenet",
    "freshbooks",
    "front",
    "fujitsu",
    "futbol",
    "futura",
    "future",
    "gadgets",
    "gaiaonline",
    "gallup",
    "gamefaq",
    "gameinformer",
    "gamespot",
    "gasbuddy",
    "gc.ca",
    "gedmatch",
    "geico",
    "general",
    "geox",
    "gimp",
    "github",
    "githubusercontent",
    "gmail",
    "godaddy",
    "goldmansachs",
    "google",
    "gosuper8",
    "grab",
    "grammarly",
    "grantthornton",
    "gratuito",
    "gstatic",
    "guardian",
    "gumtree",
    "h&m",
    "hao123",
    "harvard",
    "heb",
    "heroku",
    "hgtv",
    "hike",
    "holidaycheck",
    "honda",
    "horus",
    "htop",
    "huawei",
    "hubspot",
    "hulu",
    "hurriyet",
    "icbc",
    "iclinic",
    "icicibank",
    "icq",
    "idealo",
    "icml",
    "ieee",
    "ifood",
    "ikea",
    "imdb",
    "indeed",
    "instagram",
    "intel",
    "intuit",
    "invision",
    "investopedia",
    "ios",
    "ipage",
    "irctc",
    "iris",
    "isc",
    "ishtar",
    "issuu",
    "istockphoto",
    "itau",
    "itunes",
    "jabong",
    "jaguar",
    "jamanetwork",
    "jaunt",
    "jekyll",
    "jewelry",
    "jira",
    "jnj",
    "joomla",
    "jotform",
    "joybuy",
    "jubii",
    "judge",
    "juniper",
    "justeat",
    "justin",
    "kaiser",
    "kakao",
    "kaspersky",
    "kcell",
    "kfc",
    "khaleejtimes",
    "kia",
    "kimbho",
    "kiplinger",
    "kiruba",
    "klarna",
    "klarna",
    "klein",
    "klm",
    "kobo",
    "kompas",
    "kongregate",
    "kotak",
    "kraft",
    "krispykreme",
    "kroger",
    "ksenia",
    "kt",
    "kualalumpur",
    "kubernetes",
    "kunduz",
    "lacoste",
    "lamborghini",
    "landrover",
    "laposte",
    "lastpass",
    "latimes",
    "launchpad",
    "lego",
    "lenovo",
    "lexus",
    "lg",
    "linkedin",
    "lido",
    "lidl",
    "lifetime",
    "lime",
    "linkedin",
    "live",
    "living",
    "livescience",
    "livestrong",
    "loadproof",
    "logic",
    "logmein",
    "lollapalooza",
    "lowes",
    "lucide",
    "lufthansa",
    "lyft",
    "mcdonalds",
    "microsoft",
    "monzo",
    "mozilla",
    "msn",
    "myspace",
    "mytheresa",
    "nasa",
    "naver",
    "nba",
    "netflix",
    "newegg",
    "news",
    "nintendo",
    "nike",
    "nokia",
    "nomad",
    "norton",
    "npr",
    "nvidia",
    "nytimes",
    "oanda",
    "office",
    "oneplus",
    "openstreetmap",
    "oracle",
    "paypal",
    "pepsi",
    "periscope",
    "pinterest",
    "pixabay",
    "pku",
    "playstation",
    "priceline",
    "pricetravel",
    "priceminister",
    "princeton",
    "prisma",
    "protonmail",
    "puhraut",
    "puma",
    "pushbullet",
    "qatarairways",
    "qiita",
    "qq",
    "quora",
    "rackspace",
    "razer",
    "realtor",
    "redhat",
    "reddit",
    "reuters",
    "rte",
    "samsung",
    "savethechildren",
    "scb",
    "sciencedirect",
    "scholar",
    "seagate",
    "seat",
    "seatallocator",
    "seebug",
    "segmentfault",
    "sephora",
    "shopee",
    "shopify",
    "siemens",
    "skype",
    "slack",
    "slashdot",
    "slideshare",
    "snapchat",
    "sony",
    "sourceforge",
    "spotify",
    "stackoverflow",
    "speedtest",
    "spiegel",
    "stackoverflow",
    "stackoverflowcompany",
    "spreaker",
    "spring",
    "springer",
    "spotify",
    "sprint",
    "starbucks",
    "statefarm",
    "steam",
    "stripe",
    "subaru",
    "sumologic",
    "superuser",
    "supersaver",
    "surveygizmo",
    "svenskaspel",
    "swatch",
    "swift",
    "swift",
    "swiggy",
    "symantec",
    "t-mobile",
    "tangerine",
    "target",
    "teams",
    "ted",
    "telegram",
    "tesla",
    "theguardian",
    "thetimes",
    "thomsonreuters",
    "thunderbird",
    "ticketmaster",
    "tiktok",
    "timesofindia",
    "tistory",
    "todoist",
    "tomtom",
    "toshiba",
    "toyota",
    "trello",
    "tripadvisor",
    "trulia",
    "trustpilot",
    "twitch",
    "twitter",
    "uber",
    "unicef",
    "unilever",
    "updated",
    "uptime",
    "usbank",
    "usps",
    "utc",
    "uverse",
    "viber",
    "vimeo",
    "visa",
    "vmware",
    "volkswagen",
    "volvo",
    "walmart",
    "weibo",
    "weixin",
    "whatsapp",
    "wikipedia",
    "windows",
    "wix",
    "wordpress",
    "worldbank",
    "wsj",
    "xerox",
    "xfinity",
    "yahoo",
    "yandex",
    "youtube",
    "zara",
    "zebra",
    "zendesk",
    "zk",
    "zoho",
    "zoom",
  ];

  // --- Outcome Functions ---
  // function getPhishingPrediction() {
  //   const isURL = isDetectedByURL() === 1;
  //   const isCon = isDetectedByContent() === 1;
  //   return {
  //     isURL,
  //     isContent: isCon,
  //     details: isURL || isCon ? "May be phishing" : "Looks safe",
  //   };
  // }

  // ------------------ Model prediction ------------------
  async function getPhishingPrediction() {
    await ensureModel();
    const [urlFeats, contentFeats] = await Promise.all([
      isDetectedByURL(),
      isDetectedByContent(),
    ]);
    const feats = { ...urlFeats, ...contentFeats };
    const { pUrl, pCon } = await predictSplit(feats);
    const isURL = pUrl >= 0.5 ? 1 : 0;
    const isCon = pCon >= 0.5 ? 1 : 0;

    const isPhish = isURL || isCon;
    return {
      isURL,
      isContent: isCon,
      details: isPhish ? "phish" : "legit",
    };
  }

  // Listen for popup requests
  chrome.runtime.onMessage.addListener((req, sender, resp) => {
    if (req.action === "GetPrediction") {
      getPhishingPrediction().then((pred) => {
        resp({ result: pred });
      });
      return true;
    }
  });

  // ------------------ URL-based features (f1–f56) ------------------
  async function isDetectedByURL() {
    // f1: full URL length
    // const statReport = f56_statisticalReport(url, domain);

    const canonicalURL = url.replace(/[#?].*$/, "");
    const f1 = canonicalURL.length;

    console.error("f1 (URL length):", f1);
    // f2: hostname length
    const f2 = hostname.length;
    console.error("f2 (hostname length):", f2);
    // f3: IP in hostname
    const f3 = /^\d+\.\d+\.\d+\.\d+$/.test(hostname) ? 1 : 0;
    console.error("f3 (IP hostname):", f3);
    // f4–f20: special chars
    const specials = [
      "\\.",
      "-",
      "@",
      "\\?",
      "&",
      "\\|",
      "=",
      "_",
      "~",
      "%",
      "/",
      "\\*",
      ":",
      ",",
      ";",
      "\\$",
      "%20",
    ];
    const specialCounts = specials.map(
      (ch) => (url.match(new RegExp(ch, "g")) || []).length
    );
    console.groupCollapsed("[URL] special-character counts");
    specials.forEach((pat, i) => {
      // readable label, strip leading backslashes
      const label = pat.replace(/\\/g, "");
      console.log(`f${4 + i}  '${label}'  →`, specialCounts[i]);
    });
    console.groupEnd();

    // destructure into f4 … f20
    const [
      f4,
      f5,
      f6,
      f7,
      f8,
      f9,
      f10,
      f11,
      f12,
      f13,
      f14,
      f15,
      f16,
      f17,
      f18,
      f19,
      f20,
    ] = specialCounts;

    // f21–f24: common terms
    const f21 = (url.match(/www/gi) || []).length;
    console.error("f21 (www):", f21);
    const f22 = (url.match(/\.com/gi) || []).length;
    console.error("f22 (.com):", f22);
    const url_path = new URL(url).pathname.toLowerCase();
    const f23 = path.includes("http") ? 1 : 0;
    console.error("f23 (http):", f23);
    const f24 = url.match(/\/\//g)?.length || 0;

    console.error("f24 (//):", f24);
    // f25: https protocol
    const f25 = url.toLowerCase().startsWith("https://") ? 1 : 0;
    console.error("f25 (https token):", f25);
    // f26–f27: digit ratios
    const digitsAll = (url.match(/\d/g) || []).length;
    const f26 = url.length ? digitsAll / url.length : 0;
    console.error("f26 (digits ratio URL):", f26);
    const digitsHost = (hostname.match(/\d/g) || []).length;
    const f27 = hostname.length ? digitsHost / hostname.length : 0;
    console.error("f27 (digits ratio host):", f27);
    // f28: punycode
    const f28 = hostname.startsWith("xn--") ? 1 : 0;
    console.error("f28 (punycode):", f28);
    // f29: port
    const f29 = parsed.port && parsed.port !== "" ? 1 : 0;
    console.error("f29 (port):", f29);
    // f30–31 TLD in path/subdomain
    const tld = hostname.split(".").slice(-1)[0];
    const f30 = path.includes(`.${tld}/`) ? 1 : 0;
    console.error("f30 (tld in path):", f30);
    const subparts = hostname.split(".").slice(0, -2).join(".");
    const f31 = subparts.includes(`.${tld}`) ? 1 : 0;
    console.error("f31 (tld in subdomain):", f31);
    // f32: abnormal subdomain
    const f32 = /w[w]?\d+/.test(subparts) ? 1 : 0;
    console.error("f32 (abnormal subdomain):", f32);
    // f33: # subdomains
    const dotCount = (hostname.match(/\./g) || []).length;
    const f33 = dotCount < 3 ? dotCount : 3;
    console.error("f33 (#subdomains):", f33);
    // f34: prefix-suffix
    const f34 = /https?:\/\/[^\/]*-[^\/]*\./i.test(url) ? 1 : 0;
    console.error("f34 (prefix-suffix):", f34);
    // f35: random domain stub
    const f35 = f35_randomDomain(domain);
    console.error("f35 (random domain stub):", f35);
    // f36: shortening
    const f36 = SHORTENER_REGEX.test(url) ? 1 : 0;
    console.error("f36 (shortener):", f36);
    // f37: path extension
    const f37 = /\.(txt|exe|js)$/.test(path) ? 1 : 0;
    console.error("f37 (path ext):", f37);
    // f38–f39: redirections stub
    // 1️⃣ Meta-refresh redirects
    const metaRedirects = document.querySelectorAll(
      'meta[http-equiv="refresh"]'
    ).length;

    // 2️⃣ JS-based redirects
    let jsRedirects = 0;
    document.querySelectorAll("script").forEach((s) => {
      const t = s.textContent;
      if (/location\.(?:href|replace|assign)\s*=/.test(t)) jsRedirects++;
    });

    // 3️⃣ Param-based redirects in anchors
    let paramRedirects = 0;
    const redirectParams = ["url", "redirect", "r", "out", "go"];
    document.querySelectorAll("a[href]").forEach((a) => {
      try {
        const u = new URL(a.href, location.href);
        redirectParams.forEach((p) => {
          if (u.searchParams.has(p)) paramRedirects++;
        });
      } catch {}
    });

    let shortenerRedirects = 0;
    document.querySelectorAll("a[href]").forEach((a) => {
      try {
        const u = new URL(a.href, location.href);
        if (shorteners.has(u.hostname)) shortenerRedirects++;
      } catch {}
    });

    // 5️⃣ Double-slash path abuses
    let doubleSlashRedirects = 0;
    document.querySelectorAll("a[href]").forEach((a) => {
      const path = a.pathname || "";
      if (path.indexOf("//") > 0) doubleSlashRedirects++;
    });

    // Totals
    const f38 = metaRedirects + jsRedirects + paramRedirects;
    const f39 = shortenerRedirects + doubleSlashRedirects;
    console.error("f38 (redir count stub):", f38);
    console.error("f39 (ext redir stub):", f39);
    // f40–f50: NLP features

    // 1️⃣ Build Python‐style word lists:
    const splitRe = /[-\.\/\?=\@&%:_]+/;

    // 2️⃣ Split into word arrays just like Python’s `words_raw_extraction(...)`:
    const w_domain = domainLabel.split(splitRe).filter(Boolean);
    const w_subdomain = subdomainLabel.split(splitRe).filter(Boolean);
    const w_path = pathArg.split(splitRe).filter(Boolean);

    // 3️⃣ Build combined lists
    const rawWords = [...w_domain, ...w_path, ...w_subdomain];
    const hostWords = [...w_domain, ...w_subdomain];

    // 4️⃣ Compute length arrays
    const lensAll = rawWords.map((w) => w.length);
    const lensHost = hostWords.map((w) => w.length);
    const lensPath = w_path.map((w) => w.length);

    // f40:
    // 5️⃣ Feature variables
    const f40 = rawWords.length;
    let f41 = 0;
    for (const word of rawWords) {
      // check for runs of length 2, 3, 4, 5
      for (const runLength of [2, 3, 4, 5]) {
        for (let i = 0; i + runLength <= word.length; i++) {
          const segment = word.substr(i, runLength);
          // if all chars in segment are the same
          if ([...segment].every((ch) => ch === segment[0])) {
            f41++;
          }
        }
      }
    }
    const f42 = lensAll.length ? Math.min(...lensAll) : 0;
    const f43 = lensHost.length ? Math.min(...lensHost) : 0;
    const f44 = lensPath.length ? Math.min(...lensPath) : 0;
    const f45 = lensAll.length ? Math.max(...lensAll) : 0;
    const f46 = lensHost.length ? Math.max(...lensHost) : 0;
    const f47 = lensPath.length ? Math.max(...lensPath) : 0;
    const average = (arr) =>
      arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
    const f48 = average(lensAll);
    const f49 = average(lensHost);
    const f50 = average(lensPath);

    // 6️⃣ Now log if you still need to debug:
    console.error("f40 (#words):", f40);
    console.error("f41 (char repeat):", f41);
    console.error("f42 (shortest raw):", f42);
    console.error("f43 (shortest host):", f43);
    console.error("f44 (shortest path):", f44);
    console.error("f45 (longest raw):", f45);
    console.error("f46 (longest host):", f46);
    console.error("f47 (longest path):", f47);
    console.error("f48 (avg len raw):", f48);
    console.error("f49 (avg len host):", f49);
    console.error("f50 (avg len path):", f50);

    // f51: phish hints
    const f51 = hints.reduce(
      (count, h) => count + (url.toLowerCase().includes(h) ? 1 : 0),
      0
    );
    console.error("f51 (phish hints):", f51);
    // f52-f54: brand domain stub
    const f52 = BRANDS.includes(domain) ? 1 : 0;
    console.error("f52 (brand in domain):", f52);

    // f53: brand in subdomain (but not in registered domain)
    const f53 = BRANDS.some((b) => hostname.includes(b) && !domain.includes(b))
      ? 1
      : 0;
    console.error("f53 (brand in subdomain):", f53);

    // f54: brand in URL path (delimited)
    const f54 = BRANDS.some(
      (b) => path.includes(`/${b}/`) && !domain.includes(b)
    )
      ? 1
      : 0;
    console.error("f54 (brand in path):", f54);
    // f55: suspicious TLD
    const f55 = suspTLDs.has(tld) ? 1 : 0;
    console.error("f55 (susp TLD):", f55);
    // f56: statistical stub
    console.error("f56 (stat report stub):", 0);

    // Return a simple binary score or data object as needed
    const urlFeatures = {
      length_url: f1,
      length_hostname: f2,
      ip: f3,
      nb_dots: f4,
      nb_hyphens: f5,
      nb_at: f6,
      nb_qm: f7,
      nb_and: f8,
      nb_or: f9,
      nb_eq: f10,
      nb_underscore: f11,
      nb_tilde: f12,
      nb_percent: f13,
      nb_slash: f14,
      nb_star: f15,
      nb_colon: f16,
      nb_comma: f17,
      nb_semicolumn: f18,
      nb_dollar: f19,
      nb_space: f20,

      nb_www: f21,
      nb_com: f22,
      nb_dslash: f24,
      http_in_path: f23,
      https_token: f25,
      ratio_digits_url: f26,
      ratio_digits_host: f27,
      punycode: f28,
      port: f29,
      tld_in_path: f30,
      tld_in_subdomain: f31,
      abnormal_subdomain: f32,
      nb_subdomains: f33,
      prefix_suffix: f34,
      random_domain: f35,
      shortening_service: f36,
      path_extension: f37,
      nb_redirection: f38,
      nb_external_redirection: f39,
      length_words_raw: f40,
      char_repeat: f41,
      shortest_words_raw: f42,
      shortest_word_host: f43,
      shortest_word_path: f44,
      longest_words_raw: f45,
      longest_word_host: f46,
      longest_word_path: f47,
      avg_words_raw: f48,
      avg_word_host: f49,
      avg_word_path: f50,
      phish_hints: f51,
      domain_in_brand: f52,
      brand_in_subdomain: f53,
      brand_in_path: f54,
      suspecious_tld: f55,
      statistical_report: 0, // ← f56 stub (keep 0 or your async val)
    };
    return urlFeatures;
  }

  function f35_randomDomain(domain) {
    const s = domain.replace(/\./g, "");
    if (!s) return 0;
    // frequency map
    const freq = {};
    for (let c of s) freq[c] = (freq[c] || 0) + 1;
    const len = s.length;
    // Shannon entropy H = –Σ p(c) log2 p(c)
    let H = 0;
    for (let c in freq) {
      const p = freq[c] / len;
      H -= p * Math.log2(p);
    }
    // if entropy is above threshold, consider it “random”
    return H > 3.5 ? 1 : 0;
  }

  async function f56_statisticalReport(fullUrl, domain) {
    const URL_REGEX = /(at\.ua|usa\.cc|…|ow\.ly)/i;
    const IP_REGEX = /\b(146\.112\.61\.108|…|110\.34\.231\.42)\b/;

    const urlMatch = URL_REGEX.test(fullUrl);

    try {
      const resp = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
        { headers: { Accept: "application/dns-json" } }
      );
      const json = await resp.json();
      const answers = (json.Answer || []).map((a) => a.data);
      const ipMatch = answers.some((ip) => IP_REGEX.test(ip));
      const val = urlMatch || ipMatch ? 1 : 0;
      console.error("f56 (statistical report):", val);
      return val;
    } catch (e) {
      console.error("f56 error, returning 2", e);
      return 2;
    }
  }

  // ------------------ Content-based features (f57–f80) ------------------
  // ----- Content helpers ----
  // at the top of the content script (after you know location)
  const REG_DOMAIN = location.hostname.split(".").slice(-2).join(".");
  const NULL_FORMATS = new Set([
    "#",
    "#content",
    "javascript:void(0)",
    "javascript:;",
    "",
    " ",
    "about:blank",
    "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEAAAAALAAAAAABAAEAAAI=",
  ]);

  // Buckets for counts
  const counts = {
    href: { internals: 0, externals: 0, nulls: 0 },
    link: { internals: 0, externals: 0, nulls: 0 },
    media: { internals: 0, externals: 0, nulls: 0 },
    css: { internals: 0, externals: 0, nulls: 0 },
    form: { internals: 0, externals: 0, nulls: 0 },
    favicon: { internals: 0, externals: 0, nulls: 0 },
  };
  let safeAnchors = 0,
    unsafeAnchors = 0;
  let iframeInvisible = 0,
    iframeVisible = 0;
  const htmlLower = document.documentElement.outerHTML.toLowerCase();
  const bodyText = document.body.innerText || "";

  // Helper to categorize URLs
  function addTo(bucket, key, value = 1) {
    if (bucket[key] instanceof Set) {
      bucket[key].add(value); // media.*
    } else {
      bucket[key] += 1; // href.*, link.*, …
    }
  }

  /** absolute URL   →  {internals, externals, nulls} */
  function categorize(raw, bucketName) {
    const bucket = counts[bucketName];
    let u = (raw || "").trim();

    // -------- “null” hyperlinks ------------------------------------------
    if (!u || nullFormats.has(u)) {
      addTo(bucket, "nulls", u);
      return;
    }

    // -------- make it absolute -------------------------------------------
    try {
      u = new URL(u, location.href).href;
    } catch (e) {
      /* ignore malformed */
    }

    // -------- internal or external? --------------------------------------
    const hostTest =
      u.includes(location.hostname) || // exact host
      u.includes(REG_DOMAIN); // any sub-domain
    const isInternal = hostTest;

    addTo(bucket, isInternal ? "internals" : "externals", u);
  }

  function classifyMedia(rawSrc) {
    const bucket = counts["media"];
    let src = (rawSrc || "").trim();

    /* ① null / placeholder ------------------------------------------- */
    if (!src || NULL_FORMATS.has(src)) {
      addTo(bucket, "nulls");
      return;
    }

    /* ② canonicalise to absolute URL --------------------------------- */
    let abs;
    try {
      abs = new URL(src, location.href);
    } catch (_) {
      addTo(bucket, "nulls");
      return;
    }

    const host = abs.hostname; // wiki-cdn…
    const dots = (host.match(/\./g) || []).length;
    const isHTTP = abs.protocol === "http:" || abs.protocol === "https:";

    /* ③ reproduce Python’s four-term internal test ------------------- */
    const internal =
      host === location.hostname || // hostname in src
      host.endsWith("." + REG_DOMAIN) || // domain  in src
      dots === 1 || // len(dots)==1
      !isHTTP; // not startswith('http')

    addTo(bucket, internal ? "internals" : "externals");
  }

  // Extraction pass
  async function extractAll() {
    // Anchors
    document.querySelectorAll("a[href]").forEach((a) => {
      const h = a.getAttribute("href").trim();
      const hl = h.toLowerCase();
      const dots = (h.match(/\./g) || []).length;
      const isHttp = h.startsWith("http");
      const isInternal =
        h.includes(hostname) || h.includes(domain) || dots === 1 || !isHttp;

      if (!h || nullFormats.has(h)) {
        counts.href.nulls++;
      } else if (isInternal) {
        counts.href.internals++;
      } else {
        counts.href.externals++;
      }

      if (isInternal) {
        // Only internal links can be unsafe
        if (
          h.includes("#") ||
          hl.includes("javascript") ||
          hl.includes("mailto")
        ) {
          unsafeAnchors++;
        }
        // (internal links without those patterns are ignored)
      } else {
        // All external links count as safe
        safeAnchors++;
      }
    });
    // // Media
    document
      .querySelectorAll("img[src], audio[src], embed[src]")
      .forEach((el) => {
        let src = el.getAttribute("src") || "";

        // deal with lazy-load placeholders exactly like Python’s null test
        if (!src || NULL_FORMATS.has(src)) {
          src =
            el.getAttribute("data-src") ||
            el.getAttribute("data-original") ||
            el.getAttribute("data-lazy-src") ||
            "";
        }
        if (!src && el.currentSrc) src = el.currentSrc;

        classifyMedia(src);
      });

    // Links & CSS & Favicon
    document.querySelectorAll("link[href]").forEach((el) => {
      const href = el.getAttribute("href");
      categorize(href, "link"); // **always**
      const rel = (el.getAttribute("rel") || "").toLowerCase();
      if (rel.includes("stylesheet")) counts.css.internals++;
      if (rel.includes("icon")) counts.favicon.internals++;
    });

    // document.querySelectorAll("link[href]").forEach((el) => {
    //   // stylesheet, prefetch, shortcut icon, etc.
    //   const href = el.href.trim();
    //   categorize(href, "link");
    //   // keep the css / favicon counters that your Python code expects
    //   const rel = (el.getAttribute("rel") || "").toLowerCase();
    //   if (rel.includes("stylesheet")) categorize(href, "css");
    //   if (rel.includes("icon")) categorize(href, "favicon");
    // });

    // Scripts
    document
      .querySelectorAll("script[src]")
      .forEach((el) => categorize(el.src.trim(), "link"));
    // Form actions
    document
      .querySelectorAll("form[action]")
      .forEach((f) => categorize(f.action.trim(), "form"));
    // Style imports
    document.querySelectorAll("style").forEach((st) => {
      const m = st.textContent.match(/@import\s+url\(([^)]+)\)/i);
      if (m) categorize(m[1].replace(/['"]/g, ""), "css");
    });
    // Iframe visibility
    document.querySelectorAll("iframe").forEach((ifr) => {
      const w = ifr.getAttribute("width"),
        h = ifr.getAttribute("height");
      if (
        (w === "0" && h === "0") ||
        window.getComputedStyle(ifr).display === "none"
      )
        iframeInvisible++;
      else iframeVisible++;
    });
  }

  extractAll();

  function classifyRedirects() {
    let internal = 0,
      external = 0;
    getRedirectTargets().forEach((raw) => {
      try {
        const u = new URL(raw, location.href);
        u.hostname === hostname ? internal++ : external++;
      } catch {
        // malformed or relative – treat as internal
        internal++;
      }
    });
    return { internal, external };
  }

  function getRedirectTargets() {
    const targets = [];

    // Meta-refresh tags: <meta http-equiv="refresh" content="5;url=...">
    document.querySelectorAll('meta[http-equiv="refresh"]').forEach((meta) => {
      const m = meta.content.match(/url=(.+)$/i);
      if (m) targets.push(m[1].trim());
    });

    // JS redirects: location.href/replace/assign
    document.querySelectorAll("script").forEach((s) => {
      const txt = s.textContent;
      // Simple regex to catch common patterns:
      [
        ...txt.matchAll(
          /location\.(?:href|replace|assign)\s*=\s*['"]([^'"]+)['"]/gi
        ),
      ].forEach((m) => targets.push(m[1].trim()));
    });

    // Param-based redirects in links: e.g. ?url=..., ?redirect=...
    document.querySelectorAll("a[href]").forEach((a) => {
      const url = new URL(a.href, location.href);
      // look for query params like url, redirect, r, out, to
      ["url", "redirect", "r", "out", "to"].forEach((p) => {
        if (url.searchParams.has(p)) {
          targets.push(url.searchParams.get(p));
        }
      });
    });

    return targets;
  }

  /**********************************************************************
   *  f80 – domain_with_copyright  (JS port with debug prints)
   *********************************************************************/
  function domainWithCopyright() {
    try {
      /* full HTML (Python’s “content” variable) ----------------------- */
      const html = document.documentElement.innerHTML;

      /* ① find the *first* © / ® / ™ symbol *or* its HTML entity ------ */
      const re = /[©®™]|&copy;|&reg;|&trade;/iu;
      const match = re.exec(html);

      if (!match) {
        console.error("[f80] no ©/®/™ symbol found → return 0");
        return 0;
      }

      const pos = match.index;
      const start = Math.max(0, pos - 50);
      const end = Math.min(html.length, pos + 50);

      /* ② 100-char window, lowercase (exactly like Python) ------------ */
      const window = html.slice(start, end).toLowerCase();

      /* ③ registrable domain of the current page --------------------- */
      const regDomain = location.hostname
        .split(".")
        .slice(-2) // ["openstreetmap","org"]
        .join("."); // "openstreetmap.org"

      const present = window.includes(regDomain.toLowerCase());

      /* --- debug prints --------------------------------------------- */
      console.groupCollapsed("[f80] domain_with_copyright");
      console.error("match text        :", match[0]);
      console.error("match position    :", pos);
      console.error("window (±50 chars):", window);
      console.error("registrable domain:", regDomain);
      console.error("domain in window  :", present);
      console.groupEnd();

      /* ④ return identical to Python --------------------------------- */
      return present ? 0 : 1;
    } catch (err) {
      console.warn("[f80] exception → return 0", err);
      return 0;
    }
  }

  // ----- Content features ----
  window.isDetectedByContent = function () {
    const h = counts.href,
      l = counts.link,
      m = counts.media,
      c = counts.css,
      f = counts.form,
      v = counts.favicon;
    // f57
    const nbHyper = h.internals + h.externals + h.nulls;
    console.error("nbHyper:", nbHyper);
    // f58
    const ratioIntHyper = nbHyper ? h.internals / nbHyper : 0;
    console.error("ratioIntHyper:", ratioIntHyper);
    // f59
    const ratioExtHyper = nbHyper ? h.externals / nbHyper : 0;
    console.error("ratioExtHyper:", ratioExtHyper);
    // f60
    const totalLinks = nbHyper + h.nulls;
    const ratioNullHyper = totalLinks ? h.nulls / totalLinks : 0;
    console.error("ratioNullHyper:", ratioNullHyper);
    // f61
    console.error("nbExtCSS:", c.externals);
    // f62/63
    const { internal: intR, external: extR } = classifyRedirects();
    const ratioIntRedir = counts.href.internals
      ? intR / counts.href.internals
      : 0;
    const ratioExtRedir = counts.href.externals
      ? extR / counts.href.externals
      : 0;

    console.error("internal redirections:", ratioIntRedir);
    console.error("external redirections:", ratioExtRedir);

    // console.error("intRedirects:", h.internals);

    // console.error("extRedirects:", h.externals);
    // f64
    const ratioIntErrors = h.internals ? h.nulls / h.internals : 0;
    const ratioExtErrors = h.externals ? h.nulls / h.externals : 0;
    console.error("ratioIntErrors:", ratioIntErrors);
    // f65
    console.error("ratioExtErrors:", ratioExtErrors);
    // f66
    const phpRe = /^[A-Za-z0-9_]+\.php$/i;
    let loginForm = 0;

    Array.from(document.forms).some((form) => {
      const act = (form.getAttribute("action") || "").trim();
      // null/empty
      if (!act || nullFormats.has(act)) {
        loginForm = 1;
        return true;
      }
      // external host
      try {
        const u = new URL(act, location.href);
        if (u.hostname !== hostname) {
          loginForm = 1;
          return true;
        }
      } catch {
        // malformed => treat as internal, skip
      }
      // *.php
      if (phpRe.test(act)) {
        loginForm = 1;
        return true;
      }
      return false; // continue checking
    });
    console.error("loginForm:", loginForm);
    // f67
    const extFavicon = v.externals > 0 ? 1 : 0;
    console.error("extFavicon:", extFavicon);
    // f68
    const nInt = Number(l.internals) || 0;
    const nExt = Number(l.externals) || 0;
    const nbLinkTags = nInt + nExt;
    const ratioLinksTag = nbLinkTags ? (nInt / nbLinkTags) * 100 : 0;
    console.error("ratioLinksTag:", ratioLinksTag);
    // f69
    const submitEmail = Array.from(document.forms).some((x) =>
      (x.action || "").toLowerCase().startsWith("mailto:")
    )
      ? 1
      : 0;
    console.error("submitEmail:", submitEmail);
    // f70/71
    // compute ratios
    const mediaInts = counts.media.internals;
    const mediaExts = counts.media.externals;
    const nbMedia = mediaInts + mediaExts;

    const ratioIntMedia = nbMedia ? (mediaInts / nbMedia) * 100 : 0;
    const ratioExtMedia = nbMedia ? (mediaExts / nbMedia) * 100 : 0;

    console.error("f70 (ratioIntMedia):", ratioIntMedia);
    console.error("f71 (ratioExtMedia):", ratioExtMedia);

    // f72
    const sfh = f.nulls > 0 ? 1 : 0;
    console.error("sfh:", sfh);
    // f73
    const iframeInv = iframeInvisible > 0 ? 1 : 0;
    console.error("iframeInv:", iframeInv);
    // f74
    const hasPrompt = htmlLower.includes("prompt(") ? 1 : 0;
    console.error("popupWin:", hasPrompt);
    // f75
    const unAnchors = (unsafeAnchors / (unsafeAnchors + safeAnchors)) * 100;
    console.error("unsafeAnch:", unAnchors);
    // f76
    const onOver = htmlLower.includes("onmouseover") ? 1 : 0;
    console.error("mouseOver:", onOver);
    // f77
    const rightOff = /event\.button\s*==\s*2/.test(htmlLower) ? 1 : 0;
    console.error("rightClickOff:", rightOff);
    // f78
    const title = document.title || "";
    const emptyTit = title.trim() === "" ? 1 : 0;
    console.error("emptyTit:", emptyTit);
    // f79
    const domainTit = title.toLowerCase().includes(domainLabel) ? 0 : 1;
    console.error("domainInTit:", domainTit);
    // f80
    afterCopy = domainWithCopyright();
    console.error("domainAfterCopy:", afterCopy);

    const contentFeatures = {
      nb_hyperlinks: nbHyper, // f57
      ratio_intHyperlinks: ratioIntHyper, // f58
      ratio_extHyperlinks: ratioExtHyper, // f59
      ratio_nullHyperlinks: ratioNullHyper, // f60
      nb_extCSS: c.externals, // f61
      ratio_intRedirection: ratioIntRedir, // f62
      ratio_extRedirection: ratioExtRedir, // f63
      ratio_intErrors: ratioIntErrors, // f64
      ratio_extErrors: ratioExtErrors, // f65 stub
      login_form: loginForm, // f66
      external_favicon: extFavicon, // f67
      links_in_tags: ratioLinksTag, // f68
      submit_email: submitEmail, // f69
      ratio_intMedia: ratioIntMedia, // f70
      ratio_extMedia: ratioExtMedia, // f71
      sfh: sfh, // f72
      iframe: iframeInv, // f73
      popup_window: hasPrompt, // f74
      safe_anchor: unAnchors, // f75
      onmouseover: onOver, // f76
      right_clic: rightOff, // f77
      empty_title: emptyTit, // f78
      domain_in_title: domainTit, // f79
      domain_with_copyright: afterCopy, // f80
    };

    return contentFeatures; // <— NEW single return value
  };
})();
