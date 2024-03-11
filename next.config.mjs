await import("./src/env.js");
/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [
      {
        source: "/(.*).(svg|jpg|png|webp)",
        headers: [
          {
            key: "Cache-Control",
            value: "public, max-age=604800, stale-while-revalidate=86400",
          },
        ],
      },
      {
        source: "/(.*?)",
        headers: [
          // The app should not be ran in an Iframe
          // This is also coverd by the CSP - frame-ancestors but should be kept for older browsers
          { key: "X-Frame-Options", value: "DENY" },
          // Add protection agianst MIME type sniffing
          { key: "x-content-type-options", value: "nosniff" },
          {
            key: "Permissions-Policy",
            value:
              "camera=(), fullscreen=(self), geolocation=(), microphone=()",
          },
          // Referrer policy is used to determine how much information is on the referrer header with a request
          { key: "referrer-policy", value: "no-referrer" },
          // If a file is injected my malicious person and presented through a link the user gets the option
          // to open the file or download it. If the user selects 'open' then the html file will be executed by the browser
          // in context of the website. This means that the it can get to information like cookies.
          // This will prevent the option to open the file but will download it instead.
          { key: "x-download-options", value: "noopen" },
          {
            key: "Strict-Transport-Security",
            value: "max-age=31536000; includeSubDomains; preload",
          },
          // TODO: enable reporting through Reporting API - not working atm
          // {
          //   key: 'Reporting-Endpoints',
          //   value: `sentry-reporting="${env.SENTRY_URL_CSP}"`,
          // },
          // {
          //   key: 'Report-To',
          //   value: JSON.stringify({
          //     group: 'sentry-reporting',
          //     'max-age': 1000000,
          //     endpoints: [{ url: env.SENTRY_URL_CSP }],
          //   }),
          // },
        ],
      },
    ];
  },
};

export default nextConfig;
