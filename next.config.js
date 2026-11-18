/** @type {import('next').NextConfig} */

// Empty string is valid (app served from root); only an unset variable is an error.
if (process.env.NEXT_PUBLIC_BASE_PATH === undefined) {
  throw new Error("Missing required environment variable: NEXT_PUBLIC_BASE_PATH");
}

const { createHash } = require("crypto");
const { PHASE_DEVELOPMENT_SERVER, PHASE_PRODUCTION_SERVER } = require("next/constants");

/** SHA-256 of BFF_SHARED_SECRET values that were committed to source and must be rotated. */
const LEAKED_BFF_SECRET_SHA256 = ["93f8ae9d859601ba3330f1ab8ddb97b0aef94097025a059df42b98c067e368b0"];

/** Server-only secrets have no fallback: `next dev` / `next start` refuse to start without
 * them (not `next build` - secrets are runtime-only and must never be needed to build, so
 * they can't end up in build output). Messages never echo a value. */
function assertServerSecrets() {
  const secret = (process.env.BFF_SHARED_SECRET || "").trim();
  if (!secret) {
    throw new Error("Missing required environment variable: BFF_SHARED_SECRET (see .env.example)");
  }
  if (secret.length < 32) {
    throw new Error("BFF_SHARED_SECRET must be at least 32 characters (e.g. `openssl rand -hex 32`)");
  }
  if (LEAKED_BFF_SECRET_SHA256.includes(createHash("sha256").update(secret).digest("hex"))) {
    throw new Error("BFF_SHARED_SECRET is a value that was published in source code - rotate it");
  }
}

const nextConfig = {
  basePath: process.env.NEXT_PUBLIC_BASE_PATH || "",
  // Baseline security response headers - none were set before. Content-Security-Policy is
  // deliberately left out here: this app renders its own inline Next.js runtime chunks plus
  // third-party widgets (reCAPTCHA, etc. - see the CDN allowlist this codebase already
  // follows for artifacts), so a safe CSP needs its own careful, separately-tested pass
  // (start in Content-Security-Policy-Report-Only) rather than being added blind alongside
  // these lower-risk headers.
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          // camera=(self), not camera=(): the profile selfie capture (SelfieCaptureModal.tsx)
          // calls getUserMedia on this app's own origin. An empty allowlist makes the browser
          // reject it outright, whatever camera permission the user has granted the site.
          // Third-party iframes still get no camera access.
          { key: "Permissions-Policy", value: "camera=(self), microphone=(), geolocation=()" },
        ],
      },
      {
        // X-Frame-Options only on page routes, not /api/** - the SCORM/HTML5 content
        // player (ContentViewer.tsx) deliberately loads this app's own
        // /api/proxy/**/content/*/assets/* responses inside an <iframe>, and the reference-
        // material viewer (ResourceViewerModal.tsx) embeds Microsoft's Office Online
        // Viewer, which itself server-side-fetches those same asset URLs. DENY-ing frames
        // on /api/** would break both without adding real protection - nothing renders a
        // raw API/asset response as a clickjackable page. Excludes only this app's own
        // /api prefix; every actual page route still gets DENY.
        source: "/:path((?!api/).*)",
        headers: [{ key: "X-Frame-Options", value: "DENY" }],
      },
    ];
  },
};

module.exports = (phase) => {
  if (phase === PHASE_DEVELOPMENT_SERVER || phase === PHASE_PRODUCTION_SERVER) {
    assertServerSecrets();
  }
  return nextConfig;
};


/** @type {import('next').NextConfig} */
// const nextConfig = {
//   reactStrictMode: true,
// };

// module.exports = nextConfig;