export async function OPTIONS(request: Request) {
  try {
    const report = (await request.json())["csp-report"];

    console.error(
      "❌ CSP Report: '%s' blocked by '%s' at route: '%s'",
      report["blocked-uri"],
      report["violated-directive"],
      report["document-uri"]
    );

    return new Response("Logged Successful", { status: 200 });
  } catch (error) {
    console.error("CSP Report could not be logged, ", { error });
    return new Response("Not Logged Successful", { status: 500 });
  }
}
