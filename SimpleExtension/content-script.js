const CONTENT_THRESHOLD = 50;

async function getPhishingPrediction() {
  const isURL = isDetectedByURL() === 1;

  const contentScore = await isDetectedByContent();

  const isContent = contentScore >= CONTENT_THRESHOLD;

  const isPhishing = isURL || isContent;

  const result = {
    isURL,
    isContent,
    details: isPhishing
      ? "This page may be a phishing attempt."
      : "This page seems safe.",
  };
  console.log("Phishing Detection Result:", result);
  return result
}

// Existing message listener for chrome.runtime messages
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'GetPrediction') {
    getPhishingPrediction()
      .then(result => sendResponse({ result }))
      .catch(err   => sendResponse({ error: err.toString() }));
    return true;          // ← tell Chrome the reply is asynchronous
  }
});

// --- New: Listen for a window message from the page ---
window.addEventListener("message", async function (event) {
  if (event.source !== window) return;
  if (event.data && event.data.type === "GET_PREDICTION") {
    try {
      // Wait for the promise to resolve
      const prediction = await getPhishingPrediction();

      // Now 'prediction' is a normal object, number, or boolean, not a Promise
      window.postMessage({ type: "PREDICTION_RESULT", prediction }, "*");
    } catch (err) {
      console.error("Error in getPhishingPrediction:", err);
      window.postMessage(
        { type: "PREDICTION_RESULT", prediction: { error: err.toString() } },
        "*"
      );
    }
  }
});

function isDetectedByURL() {
  const parsedUrl = new URL(window.location.href);
  const hostname = parsedUrl.hostname;
  const parts = hostname.split(".");
  let score = 0;
  if (parts.length < 3) {
    return score;
  }
  const subdomainParts = parts.slice(0, parts.length - 2);
  const subdomain = subdomainParts.join(".");
  if (subdomain.length > 5) {
    score += 0.5;
  }
  const domain = parts[parts.length - 2].toLowerCase();
  const freeHostingProviders = [
    "000webhost",
    "freehostia",
    "neocities",
    "wordpress",
    "blogspot",
    "netlify",
    "weebly",
    "github",
    "weeblysite",
  ];
  const isFreeHosting = freeHostingProviders.includes(domain);
  const hasHyphenSegments = window.location.href.split("-").length > 1;
  if (isFreeHosting || hasHyphenSegments) {
    score += 0.5;
  }
  return score;
}

// function isDetectedByContent() {
//   let score = 0;
//   const htmlLength = document.documentElement.outerHTML.length;
//   if (htmlLength < 7500) {
//     score += 0.35;
//   }
//   const forms = document.querySelectorAll("form");
//   let insecureForms = 0;
//   forms.forEach((form) => {
//     const action = form.getAttribute("action");
//     if (!action || action.startsWith("http://")) {
//       insecureForms++;
//     }
//   });
//   if (insecureForms > 0) {
//     score += 0.35;
//   }
//   const images = document.querySelectorAll("img");
//   let externalImages = 0;
//   const currentDomain = window.location.hostname;
//   images.forEach((img) => {
//     const src = img.getAttribute("src");
//     if (src && src.startsWith("http") && !src.includes(currentDomain)) {
//       externalImages++;
//     }
//   });
//   if (externalImages <= 5) {
//     score += 0.35;
//   }
//   return Math.min(score, 1);
// }

async function isDetectedByContent() {
  /*****************************************************
   * 0) PARSE THE DOM to gather your data structures
   *****************************************************/
  const domain = window.location.hostname || "";
  const content = document.documentElement.outerHTML || "";
  const title = document.title || "";

  // Helper function to check if a URL is internal vs. external
  // For a real project, you might do a more robust check:
  // e.g. compare the domain/hostname or use new URL(...).
  function isInternal(url) {
    try {
      const parsed = new URL(url, window.location.href);
      return parsed.hostname === domain;
    } catch {
      return false; // if it fails to parse, treat as external or null
    }
  }

  /*****************************************************
   * 1) Build "Href" object
   *    The original Python code expects:
   *      { internals: [], externals: [], null: [] }
   *    We'll gather <a> tags for demonstration,
   *    though "Href" might have come from other elements too.
   *****************************************************/
  const Href = { internals: [], externals: [], null: [] };
  document.querySelectorAll("a[href]").forEach((a) => {
    const link = a.getAttribute("href");
    if (!link) {
      Href.null.push("");
    } else if (isInternal(link)) {
      Href.internals.push(link);
    } else {
      Href.externals.push(link);
    }
  });
  // If your dataset included 'null' for missing href attributes,
  // the above logic covers that. If you want something else
  // (like "javascript:void(0)"), handle it accordingly.

  /*****************************************************
   * 2) Build "Link" object
   *    Typically refers to <link> tags in <head> or <body>.
   *****************************************************/
  const Link = { internals: [], externals: [], null: [] };
  document.querySelectorAll("link[href]").forEach((ln) => {
    const link = ln.getAttribute("href");
    if (!link) {
      Link.null.push("");
    } else if (isInternal(link)) {
      Link.internals.push(link);
    } else {
      Link.externals.push(link);
    }
  });
  /*****************************************************
   * 3) Build "Media" object
   *    E.g., <img>, <video>, <audio>, <script>, ...
   *    We'll do images as an example.
   *****************************************************/
  const Media = { internals: [], externals: [], null: [] };
  document.querySelectorAll("img[src]").forEach((img) => {
    const link = img.getAttribute("src");
    if (!link) {
      Media.null.push("");
    } else if (isInternal(link)) {
      Media.internals.push(link);
    } else {
      Media.externals.push(link);
    }
  });
  /*****************************************************
   * 4) Build "Form" object
   *    Typically from <form action="...">
   *****************************************************/
  const Form = { internals: [], externals: [], null: [] };
  document.querySelectorAll("form").forEach((f) => {
    const link = f.getAttribute("action");
    if (!link) {
      Form.null.push("");
    } else if (isInternal(link)) {
      Form.internals.push(link);
    } else {
      Form.externals.push(link);
    }
  });
  /*****************************************************
   * 5) Build "CSS" object
   *    Usually from <link rel="stylesheet" href="...">
   *****************************************************/
  const CSS = { internals: [], externals: [], null: [] };
  document.querySelectorAll('link[rel="stylesheet"]').forEach((css) => {
    const link = css.getAttribute("href");
    if (!link) {
      CSS.null.push("");
    } else if (isInternal(link)) {
      CSS.internals.push(link);
    } else {
      CSS.externals.push(link);
    }
  });
  /*****************************************************
   * 6) Build "Favicon" object
   *    E.g., <link rel="icon" href="...">
   *    or <link rel="shortcut icon" href="...">
   *****************************************************/
  const Favicon = { internals: [], externals: [], null: [] };
  document
    .querySelectorAll('link[rel="icon"], link[rel="shortcut icon"]')
    .forEach((fav) => {
      const link = fav.getAttribute("href");
      if (!link) {
        Favicon.null.push("");
      } else if (isInternal(link)) {
        Favicon.internals.push(link);
      } else {
        Favicon.externals.push(link);
      }
    });
  /*****************************************************
   * 7) Build "IFrame" object
   *    Check for <iframe>.
   *    If you want to detect "invisible" iframes,
   *    you can check styles or widths and heights, etc.
   *****************************************************/
  const IFrame = { invisible: [] };
  document.querySelectorAll("iframe").forEach((iframe) => {
    // simplistic check: if it's styled as hidden
    // or has width/height = 0
    const w = iframe.getAttribute("width") || "";
    const h = iframe.getAttribute("height") || "";
    const style = window.getComputedStyle(iframe);
    if (
      style.display === "none" ||
      style.visibility === "hidden" ||
      w === "0" ||
      h === "0"
    ) {
      IFrame.invisible.push(iframe.getAttribute("src") || "");
    }
  });
  /*****************************************************
   * 8) Build "Anchor" object
   *    In your Python code, "Anchor" has safe vs. unsafe.
   *    The logic to define "safe" or "unsafe" is up to you.
   *    We'll do a trivial example:
   *****************************************************/
  const Anchor = { safe: [], unsafe: [] };
  document.querySelectorAll("a[href]").forEach((a) => {
    const link = a.getAttribute("href");
    // example heuristic: if link is external, consider it unsafe
    // purely for demonstration
    if (isInternal(link)) {
      Anchor.safe.push(link);
    } else {
      Anchor.unsafe.push(link);
    }
  });

  const total = h_total(Href, Link, Media, Form, CSS, Favicon);

  const intHyperlinks =
    h_internal(Href, Link, Media, Form, CSS, Favicon) / total;
  // console.error("@@@ Internal Hyperlinks:", intHyperlinks);

  const extHyperlinks =
    h_external(Href, Link, Media, Form, CSS, Favicon) / total;
  // console.error("@@@ External Hyperlinks:", extHyperlinks);

  const nulHyperlinks = h_null(Href, Link, Media, Form, CSS, Favicon) / total;
  // console.error("@@@ null Hyperlinks:", nulHyperlinks);

  const nbHyperlinks = total;
  window.postMessage(
    {
      __DEBUG__: `@@@ nb_hyperlinks = ${nbHyperlinks}`, // or whatever your marker is
    },
    "*"
  );

  const extCSSCount = external_css(CSS);
  console.error("@@@ External CSS:", extCSSCount);
  window.postMessage(
    {
      __DEBUG__: `@@@ External CSS = ${extCSSCount}`, // or whatever your marker is
    },
    "*"
  );


  const loginFormVal = login_form(Form);
  window.postMessage(
    {
      __DEBUG__: `@@@ Login forms = ${loginFormVal}`, // or whatever your marker is
    },
    "*"
  );

  const extFaviconVal = external_favicon(Favicon);
  console.error("@@@ External favicons:", extFaviconVal);
  window.postMessage(
    {
      __DEBUG__: `@@@ External favicons = ${extFaviconVal}`, // or whatever your marker is
    },
    "*"
  );


  const mailSubmitVal = submitting_to_email(Form);
  console.error("@@@ Email submissions:", mailSubmitVal);
  window.postMessage(
    {
      __DEBUG__: `@@@ Email submissions = ${mailSubmitVal}`, // or whatever your marker is
    },
    "*"
  );


  const intMediaPct = internal_media(Media); // 0..100
  console.error("@@@ Internal Media:", intMediaPct);
  window.postMessage(
    {
      __DEBUG__: `@@@ Internal Media = ${intMediaPct}`, // or whatever your marker is
    },
    "*"
  );


  const extMediaPct = external_media(Media); // 0..100
  console.error("@@@ External Media:", extMediaPct);
  window.postMessage(
    {
      __DEBUG__: `@@@ External Media = ${extMediaPct}`, // or whatever your marker is
    },
    "*"
  );


  const isEmptyTitle = empty_title(title);
  console.error("@@@ isEmptyTitle:", isEmptyTitle);
  window.postMessage(
    {
      __DEBUG__: `@@@ isEmptyTitle = ${isEmptyTitle}`, // or whatever your marker is
    },
    "*"
  );


  // const unsafeAnchorPct = safe_anchor(Anchor); // 0..100
  // console.error("@@@ unsafeAnchorPct:", unsafeAnchorPct);
  // window.postMessage(
  //   {
  //     __DEBUG__: `@@@ unsafeAnchorPct = ${unsafeAnchorPct}`, // or whatever your marker is
  //   },
  //   "*"
  // );


  
  // const linksTagsPct = links_in_tags(Link); // 0..100
  // console.error("@@@ linksTagsPct:", linksTagsPct);
  // window.postMessage(
  //   {
  //     __DEBUG__: `@@@ linksTagsPct = ${linksTagsPct}`, // or whatever your marker is
  //   },
  //   "*"
  // );



  // const formHandlerVal = sfh(domain, Form);
  // const hasIframe = iframe(IFrame);
  // const onMouseVal = onmouseover(content);
  // const popUpVal = popup_window(content);
  // const rightClickVal = right_clic(content);
  // const domInTitleVal = domain_in_title(domain, title);
  // const domCopyrightVal = domain_with_copyright(domain, content);

  /*****************************************************
   * 2) Gather the async features with Promise.all
   *****************************************************/
  // const [intRedirectVal, extRedirectVal, intErrorsVal, extErrorsVal] =
  //   await Promise.all([
  //     internal_redirection(Href, Link, Media, Form, CSS, Favicon),
  //     external_redirection(Href, Link, Media, Form, CSS, Favicon),
  //     internal_errors(Href, Link, Media, Form, CSS, Favicon),
  //     external_errors(Href, Link, Media, Form, CSS, Favicon),
  //   ]);

  /*****************************************************
   * 3) Assign weights and compute the final score
   *    (These weights are purely illustrative!)
   *****************************************************/
  let score = 0;

  // Example weighting scheme:
  score += intHyperlinks * 10;
  score += extHyperlinks * 10;
  score += nulHyperlinks * 15;
  score += nbHyperlinks * 15;
  score += extCSSCount * 3;

  // Scale the percentage-based features
  // score += (intMediaPct / 100) * 10; // if large internal media ratio => +some points
  // score += (extMediaPct / 100) * 15; // external media ratio => +some points
  // score += (unsafeAnchorPct / 100) * 20;
  // score += (linksTagsPct / 100) * 10;

  // Binary presence-based features
  // if (loginFormVal > 0) score += 15;
  // if (extFaviconVal > 0) score += 5;
  // if (mailSubmitVal > 0) score += 15;
  // if (isEmptyTitle > 0) score += 3;
  // if (formHandlerVal > 0) score += 5;
  // if (hasIframe > 0) score += 5;
  // if (onMouseVal > 0) score += 5;
  // if (popUpVal > 0) score += 7;
  // if (rightClickVal > 0) score += 3;
  // if (domInTitleVal > 0) score += 5;
  // if (domCopyrightVal > 0) score += 4;

  // Redirections / errors
  // score += intRedirectVal * 10;
  // score += extRedirectVal * 10;
  // score += intErrorsVal * 5;
  // score += extErrorsVal * 5;

  // /*****************************************************
  //  * 4) Check threshold
  //  *****************************************************/
  const threshold = 50;

  if (score >= threshold) {
    console.error("Likely PHISHING, score:", score);
  } else {
    console.error("Likely LEGITIMATE, score:", score);
  }

  // Return the numeric score (you could also return a classification)
  return score;
}

// ######################### Content Features #########################
// /************************************************************
//  * Number of hyperlinks present in a website (Kumar Jain'18)
//  ************************************************************/
function h_total(Href, Link, Media, Form, CSS, Favicon) {
  // Sum of all links in the 6 objects (internal + external + null).
  return (
    Href.internals.length +
    Href.externals.length +
    Href.null.length +
    Link.internals.length +
    Link.externals.length +
    Link.null.length +
    Media.internals.length +
    Media.externals.length +
    Media.null.length +
    Form.internals.length +
    Form.externals.length +
    Form.null.length +
    CSS.internals.length +
    CSS.externals.length +
    CSS.null.length +
    Favicon.internals.length +
    Favicon.externals.length +
    Favicon.null.length
  );
}

function h_internal(Href, Link, Media, Form, CSS, Favicon) {
  // Sum of all internal links.
  return (
    Href.internals.length +
    Link.internals.length +
    Media.internals.length +
    Form.internals.length +
    CSS.internals.length +
    Favicon.internals.length
  );
}

/************************************************************
 * External hyperlinks ratio (Kumar Jain'18)
 ************************************************************/
function h_external(Href, Link, Media, Form, CSS, Favicon) {
  return (
    Href.externals.length +
    Link.externals.length +
    Media.externals.length +
    Form.externals.length +
    CSS.externals.length +
    Favicon.externals.length
  );
}

/************************************************************
 * Number of null hyperlinks (Kumar Jain'18)
 ************************************************************/
function h_null(Href, Link, Media, Form, CSS, Favicon) {
  return (
    Href.null.length +
    Link.null.length +
    Media.null.length +
    Form.null.length +
    CSS.null.length +
    Favicon.null.length
  );
}

/************************************************************
 * External CSS (Kumar Jain'18)
 ************************************************************/
function external_css(CSS) {
  return CSS.externals.length;
}

/************************************************************
 * Internal redirections (Kumar Jain'18)
 *
 * In Python, we check each internal link with requests.get(link)
 * and see if there's a redirect (r.history.length > 0).
 *
 * In JS, we'll do an async function with fetch. We can't do it
 * synchronously. We'll resolve with how many had non-empty
 * redirect chains.
 ************************************************************/
async function h_i_redirect(Href, Link, Media, Form, CSS, Favicon) {
  let count = 0;
  // Collect all internal links
  const internalLinks = [
    ...Href.internals,
    ...Link.internals,
    ...Media.internals,
    ...Form.internals,
    ...CSS.internals,
    ...Favicon.internals,
  ];

  for (const link of internalLinks) {
    try {
      // Using HEAD or GET. 'fetch' doesn't directly show 'redirect chain'
      // the same way as requests.get(...).history in Python,
      // but we can check 'response.url' vs. 'link' or check 'redirected' property.
      const response = await fetch(link, { method: "GET", redirect: "follow" });
      if (response.redirected) {
        count += 1;
      }
    } catch (e) {
      // error => skip
    }
  }
  return count;
}

async function internal_redirection(Href, Link, Media, Form, CSS, Favicon) {
  const internals = h_internal(Href, Link, Media, Form, CSS, Favicon);
  if (internals > 0) {
    const redirCount = await h_i_redirect(
      Href,
      Link,
      Media,
      Form,
      CSS,
      Favicon
    );
    return redirCount / internals;
  }
  return 0;
}

/************************************************************
 * External redirections (Kumar Jain'18)
 ************************************************************/
async function h_e_redirect(Href, Link, Media, Form, CSS, Favicon) {
  let count = 0;
  // Collect all external links
  const externalLinks = [
    ...Href.externals,
    ...Link.externals,
    ...Media.externals,
    ...Form.externals,
    ...CSS.externals,
    ...Favicon.externals,
  ];

  for (const link of externalLinks) {
    try {
      const response = await fetch(link, { method: "GET", redirect: "follow" });
      if (response.redirected) {
        count += 1;
      }
    } catch (e) {
      // skip
    }
  }
  return count;
}

async function external_redirection(Href, Link, Media, Form, CSS, Favicon) {
  const externals = h_external(Href, Link, Media, Form, CSS, Favicon);
  if (externals > 0) {
    const redirCount = await h_e_redirect(
      Href,
      Link,
      Media,
      Form,
      CSS,
      Favicon
    );
    return redirCount / externals;
  }
  return 0;
}

/************************************************************
 * Generates internal errors (Kumar Jain'18)
 * Checking if status_code >= 400
 ************************************************************/
async function h_i_error(Href, Link, Media, Form, CSS, Favicon) {
  let count = 0;
  const internalLinks = [
    ...Href.internals,
    ...Link.internals,
    ...Media.internals,
    ...Form.internals,
    ...CSS.internals,
    ...Favicon.internals,
  ];

  for (const link of internalLinks) {
    try {
      const response = await fetch(link, { method: "GET" });
      if (response.status >= 400) {
        count += 1;
      }
    } catch (e) {
      // skip
    }
  }
  return count;
}

async function internal_errors(Href, Link, Media, Form, CSS, Favicon) {
  const internals = h_internal(Href, Link, Media, Form, CSS, Favicon);
  if (internals > 0) {
    const errCount = await h_i_error(Href, Link, Media, Form, CSS, Favicon);
    return errCount / internals;
  }
  return 0;
}

/************************************************************
 * Generates external errors (Kumar Jain'18)
 ************************************************************/
async function h_e_error(Href, Link, Media, Form, CSS, Favicon) {
  let count = 0;
  const externalLinks = [
    ...Href.externals,
    ...Link.externals,
    ...Media.externals,
    ...Form.externals,
    ...CSS.externals,
    ...Favicon.externals,
  ];

  for (const link of externalLinks) {
    try {
      const response = await fetch(link, { method: "GET" });
      if (response.status >= 400) {
        count += 1;
      }
    } catch (e) {
      // skip
    }
  }
  return count;
}

async function external_errors(Href, Link, Media, Form, CSS, Favicon) {
  const externals = h_external(Href, Link, Media, Form, CSS, Favicon);
  if (externals > 0) {
    const errCount = await h_e_error(Href, Link, Media, Form, CSS, Favicon);
    return errCount / externals;
  }
  return 0;
}

/************************************************************
 * Having login form link (Kumar Jain'18)
 ************************************************************/
function login_form(Form) {
  // In Python: If len(Form['externals'])>0 or len(Form['null'])>0 => return 1
  // else check if any form matches a pattern with p.match(form)
  // For a rough translation:
  const p = new RegExp("([a-zA-Z0-9_])+\\.php");
  if (Form.externals.length > 0 || Form.null.length > 0) {
    return 1;
  }
  const allForms = [...Form.internals, ...Form.externals];
  for (const f of allForms) {
    if (p.test(f)) {
      return 1;
    }
  }
  return 0;
}

/************************************************************
 * Having external favicon (Kumar Jain'18)
 ************************************************************/
function external_favicon(Favicon) {
  return Favicon.externals.length > 0 ? 1 : 0;
}

/************************************************************
 * Submitting to email
 ************************************************************/
function submitting_to_email(Form) {
  const allForms = [...Form.internals, ...Form.externals];
  for (const f of allForms) {
    if (f.includes("mailto:") || f.includes("mail()")) {
      return 1;
    }
  }
  return 0;
}

/************************************************************
 * Percentile of internal media <= 61 :
 * Request URL in Zaini'2019
 ************************************************************/
function internal_media(Media) {
  const total = Media.internals.length + Media.externals.length;
  if (total === 0) return 0;
  const internals = Media.internals.length;
  return (internals / total) * 100;
}

/************************************************************
 * Percentile of external media : Request URL in Zaini'2019
 ************************************************************/
function external_media(Media) {
  const total = Media.internals.length + Media.externals.length;
  if (total === 0) return 0;
  const externals = Media.externals.length;
  return (externals / total) * 100;
}

/************************************************************
 * Check for empty title
 ************************************************************/
function empty_title(Title) {
  // If Title is truthy => 0, else => 1
  return Title ? 0 : 1;
}

/************************************************************
 * Percentile of safe anchor :
 * URL_of_Anchor in Zaini'2019 (Kumar Jain'18)
 ************************************************************/
function safe_anchor(Anchor) {
  const total = Anchor.safe.length + Anchor.unsafe.length;
  if (total === 0) return 0;
  const unsafe = Anchor.unsafe.length;
  return (unsafe / total) * 100;
}

/************************************************************
 * Percentile of internal links :
 * links_in_tags in Zaini'2019 but without <Meta> tag
 ************************************************************/
function links_in_tags(Link) {
  const total = Link.internals.length + Link.externals.length;
  if (total === 0) return 0;
  const internals = Link.internals.length;
  return (internals / total) * 100;
}

/************************************************************
 * Server Form Handler (sfh) in Zaini'2019
 ************************************************************/
function sfh(hostname, Form) {
  if (Form.null.length > 0) {
    return 1;
  }
  return 0;
}

/************************************************************
 * IFrame Redirection
 ************************************************************/
function iframe(IFrame) {
  return IFrame.invisible.length > 0 ? 1 : 0;
}

/************************************************************
 * Onmouse action
 ************************************************************/
function onmouseover(content) {
  // Python: if 'onmouseover="window.status=' in str(content).lower():
  // We do .toLowerCase() in JS:
  const s = String(content).toLowerCase().replace(/\s+/g, "");
  if (s.includes('onmouseover="window.status=')) {
    return 1;
  }
  return 0;
}

/************************************************************
 * Pop up window
 ************************************************************/
function popup_window(content) {
  // Python: if "prompt(" in str(content).lower()
  const s = String(content).toLowerCase();
  return s.includes("prompt(") ? 1 : 0;
}

/************************************************************
 * Right-click action
 ************************************************************/
function right_clic(content) {
  // Python: re.findall(r"event.button ?== ?2", content)
  const regex = /event\.button\s*==\s*2/;
  return regex.test(content) ? 1 : 0;
}

/************************************************************
 * Domain in page title (Shirazi'18)
 ************************************************************/
function domain_in_title(domain, title) {
  // if domain is found in title => return 0, else 1
  if (title.toLowerCase().includes(domain.toLowerCase())) {
    return 0;
  }
  return 1;
}

/************************************************************
 * Domain after copyright logo (Shirazi'18)
 ************************************************************/
function domain_with_copyright(domain, content) {
  // Python tries to find the position of ©, ®, or ™
  // (some are: \N{COPYRIGHT SIGN}, \N{TRADE MARK SIGN}, \N{REGISTERED SIGN}).
  // In JS, let's do a quick search with a suitable pattern.
  const signRegex = /[\u00A9\u00AE\u2122]/; // covers ©, ®, ™
  const match = content.match(signRegex);
  if (!match) {
    // If there's no such sign, original code returns 0
    // because the try/except block does nothing in Python
    // or eventually returns 0 if no match.
    return 0;
  }
  // In Python, it took 50 chars on each side. We'll do something similar in JS:
  const index = match.index;
  let snippetStart = Math.max(0, index - 50);
  let snippetEnd = Math.min(content.length, index + 50);
  let snippet = content.substring(snippetStart, snippetEnd);

  if (snippet.toLowerCase().includes(domain.toLowerCase())) {
    return 0;
  } else {
    return 1;
  }
}

/************************************************************
 * Export or attach the functions to a global object
 * as needed by your environment. For Node.js:
 ************************************************************/

// If you want them all in one object:
// const contentFeatures = {
//   nb_hyperlinks,
//   h_total,
//   h_internal,
//   internal_hyperlinks,
//   h_external,
//   external_hyperlinks,
//   h_null,
//   null_hyperlinks,
//   external_css,
//   h_i_redirect,
//   internal_redirection,
//   h_e_redirect,
//   external_redirection,
//   h_i_error,
//   internal_errors,
//   h_e_error,
//   external_errors,
//   login_form,
//   external_favicon,
//   submitting_to_email,
//   internal_media,
//   external_media,
//   empty_title,
//   safe_anchor,
//   links_in_tags,
//   sfh,
//   iframe,
//   onmouseover,
//   popup_window,
//   right_clic,
//   domain_in_title,
//   domain_with_copyright,
// };

// For a Node environment, uncomment this:
// module.exports = contentFeatures;
