export function getUserFromAuthHeader(req: Request): { user_id?: string; email?: string; name?: string } | null {
  try {
    const authHeader = req.headers.get("authorization") || "";
    if (!authHeader.startsWith("Bearer ")) return null;
    const token = authHeader.split(" ")[1];
    if (!token) return null;

    // Check base64 JSON payload
    let payloadStr = "";
    if (token.includes(".")) {
      const parts = token.split(".");
      payloadStr = Buffer.from(parts[1], "base64").toString("utf-8");
    } else {
      payloadStr = Buffer.from(token, "base64").toString("utf-8");
    }

    const payload = JSON.parse(payloadStr);
    return {
      user_id: payload.sub || payload.user_id,
      email: payload.email,
      name: payload.name
    };
  } catch {
    return null;
  }
}
