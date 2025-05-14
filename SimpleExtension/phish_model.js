import * as ort from "./libs/ort.all.bundle.min.mjs";

// point ORT to libs/  (must run before Session.create)
ort.env.wasm.wasmPaths = { ".": chrome.runtime.getURL("libs/") };


// ─── 56 URL-side features (f1 – f56) ───────────────────────────
const URL_FEATS = [
  "length_url",
  "length_hostname",
  "ip",
  "nb_dots",
  "nb_hyphens",
  "nb_at",
  "nb_qm",
  "nb_and",
  "nb_or",
  "nb_eq",
  "nb_underscore",
  "nb_tilde",
  "nb_percent",
  "nb_slash",
  "nb_star",
  "nb_colon",
  "nb_comma",
  "nb_semicolumn",
  "nb_dollar",
  "nb_space",
  "nb_www",
  "nb_com",
  "nb_dslash",
  "http_in_path",
  "https_token",
  "ratio_digits_url",
  "ratio_digits_host",
  "punycode",
  "port",
  "tld_in_path",
  "tld_in_subdomain",
  "abnormal_subdomain",
  "nb_subdomains",
  "prefix_suffix",
  "random_domain",
  "shortening_service",
  "path_extension",
  "nb_redirection",
  "nb_external_redirection",
  "length_words_raw",
  "char_repeat",
  "shortest_words_raw",
  "shortest_word_host",
  "shortest_word_path",
  "longest_words_raw",
  "longest_word_host",
  "longest_word_path",
  "avg_words_raw",
  "avg_word_host",
  "avg_word_path",
  "phish_hints",
  "domain_in_brand",
  "brand_in_subdomain",
  "brand_in_path",
  "suspecious_tld",
  "statistical_report",
];

// ─── 24 content-side features (f57 – f80) ──────────────────────
const CT_FEATS = [
  "nb_hyperlinks",
  "ratio_intHyperlinks",
  "ratio_extHyperlinks",
  "ratio_nullHyperlinks",
  "nb_extCSS",
  "ratio_intRedirection",
  "ratio_extRedirection",
  "ratio_intErrors",
  "ratio_extErrors",
  "login_form",
  "external_favicon",
  "links_in_tags",
  "submit_email",
  "ratio_intMedia",
  "ratio_extMedia",
  "sfh",
  "iframe",
  "popup_window",
  "safe_anchor",
  "onmouseover",
  "right_clic",
  "empty_title",
  "domain_in_title",
  "domain_with_copyright",
];

const FILES = {
  url: {
    model: chrome.runtime.getURL("model/url_model.onnx"),
    scaler: chrome.runtime.getURL("model/scaler_url_model.json"),
  },
  content: {
    model: chrome.runtime.getURL("model/content_lgbm.onnx"),
    scaler: chrome.runtime.getURL("model/scaler_content_lgbm.json"),
  },
};

let sessions = {},
  scalers = {};

async function ensure(kind) {
  if (sessions[kind]) return;
  sessions[kind] = await ort.InferenceSession.create(FILES[kind].model, {
    executionProviders: ["wasm"],
  });
  scalers[kind] = await (await fetch(FILES[kind].scaler)).json();
}

// phish_model.js  (only the run() helper is shown here)

async function run(kind, dict) {
  await ensure(kind);

  const names = kind === "url" ? URL_FEATS : CT_FEATS;
  const { mean, std } = scalers[kind];

  if (!window.__dumpedURL) {
    window.__dumpedURL = true; // dump only once
    const rawVec = URL_FEATS.map((k) => dict[k] ?? 0);
    console.log("[DEBUG] copy-paste into Python:\n", JSON.stringify(rawVec));
  }

  /* --- build feature vector ---------------------------------- */
  const v = new Float32Array(names.length);
  names.forEach((k, i) => {
    const raw = dict[k] ?? 0;
    v[i] = (raw - mean[i]) / std[i];
  });

  /* --- run ONNX ---------------------------------------------- */
  const out = await sessions[kind].run({
    x: new ort.Tensor("float32", v, [1, names.length]),
  });

  /* --- DEBUG: list every output ------------------------------- */
  console.groupCollapsed(`[${kind}] ORT raw outputs`);
  Object.entries(out).forEach(([k, v]) => {
    console.log(
      k,
      v instanceof ort.Tensor
        ? { dims: v.dims, type: v.type, data: Array.from(v.data) }
        : v
    );
  });
  console.groupEnd();

  /* --- pick the tensor that really holds probabilities -------- */
  // ❶ Prefer the explicit ‘probabilities’ output if present
  let tensor = out.probabilities ?? out.probability;

  // ❷ Otherwise fall back to the first *float* tensor we can find
  if (!tensor) {
    tensor = Object.values(out).find(
      (t) => t instanceof ort.Tensor && t.type.startsWith("float")
    );
  }

  if (!tensor) {
    throw new Error(
      `[${kind}] no probability-like tensor found in ORT outputs`
    );
  }

  let prob;
  if (tensor.dims.length === 2 && tensor.dims[1] === 2) {
    // two-column matrix → class-1 probability
    prob = tensor.data[1];
  } else if (tensor.dims.reduce((a, b) => a * b, 1) === 1) {
    // single scalar
    prob = tensor.data[0];
  } else {
    throw new Error(
      `[${kind}] unexpected tensor shape ${tensor.dims} — cannot decide which index is phish probability`
    );
  }

  console.log(`[${kind}]  chosen prob =`, prob);
  // convert BigInt → Number in the extremely rare case we picked an int64
  return typeof prob === "bigint" ? Number(prob) : prob;
}


// ─── exported helper ───────────────────────────────────────────
export async function predictSplit(dict) {
  const [pUrl, pCon] = await Promise.all([
    run("url", dict),
    run("content", dict),
  ]);
  return { pUrl, pCon };
}
