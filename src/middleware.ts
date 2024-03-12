import { chain, withCsp } from "./middlewares";

export default chain([withCsp]);

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - public static files *.*
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - robots.txt (robots file)
     */
    "/((?!api|.*\\..*|_next/static|_next/image|favicon.ico|robots.txt).*)",
  ],
};
