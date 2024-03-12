import { NextFetchEvent, NextMiddleware, NextRequest } from "next/server";
import { MiddlewareFactory } from "./types";
import {
  NONE,
  REPORT_SAMPLE,
  SELF,
  STRICT_DYNAMIC,
  UNSAFE_INLINE,
  getCSP,
  nonce,
} from "csp-header";
import { env } from "@/env";

const genereateCsp = () => {
  const nonceKey = Buffer.from(crypto.randomUUID()).toString("base64");
  const csp = getCSP({
    directives: {
      "default-src": ["sentry.io", SELF],
      "script-src": [
        STRICT_DYNAMIC,
        nonce(nonceKey),
        "http:",
        "https:",
        REPORT_SAMPLE,
      ],
      "base-uri": [NONE],
      "object-src": [NONE],
      "style-src": [NONE],
      "img-src": [SELF, "data:"],
      "frame-ancestors": [NONE],
      "report-to": "report-endpoint",
    },
    reportUri: env.REPORT_ENDPOINT,
  });

  return { csp, nonceKey };
};

export const withCsp: MiddlewareFactory = (next: NextMiddleware) => {
  return async (request: NextRequest, _next: NextFetchEvent) => {
    const res = await next(request, _next);

    if (res && env.NODE_ENV === "production") {
      const { csp, nonceKey } = genereateCsp();

      const header = env.CSP_REPORT_ONLY
        ? "content-security-policy-report-only"
        : "content-security-policy";

      res.headers.set(header, csp);
      res.headers.set("x-nonce", nonceKey);
    }

    return res;
  };
};
