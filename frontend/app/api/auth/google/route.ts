import { NextResponse } from "next/server";
import { serverStorage } from "@/lib/server-storage";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({}));
    const credential = body.credential?.trim();

    if (!credential) {
      return NextResponse.json({ error: "Google credential token is required" }, { status: 400 });
    }

    // Verify credential token with Google's tokeninfo API
    let idInfo: any = null;
    try {
      const resp = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`, {
        method: "GET",
        headers: { "Accept": "application/json" }
      });
      if (resp.ok) {
        idInfo = await resp.json();
      }
    } catch (e) {
      console.warn("Google tokeninfo fetch error:", e);
    }

    // If verified or unverified JWT fallback
    let email = idInfo?.email;
    let name = idInfo?.name;
    let picture = idInfo?.picture || null;
    let sub = idInfo?.sub;

    if (!email) {
      // Decode JWT payload as fallback
      try {
        const parts = credential.split(".");
        if (parts.length >= 2) {
          const payloadStr = Buffer.from(parts[1], "base64").toString("utf-8");
          const payload = JSON.parse(payloadStr);
          email = payload.email;
          name = payload.name;
          picture = payload.picture || null;
          sub = payload.sub;
        }
      } catch (e) {
        // ignore
      }
    }

    if (!email) {
      return NextResponse.json({ error: "Could not extract a valid Google user email from token" }, { status: 400 });
    }

    const userName = name || email.split("@")[0];
    const userId = sub || `usr_${Date.now()}`;

    const user = {
      user_id: userId,
      email: email.toLowerCase(),
      name: userName,
      picture: picture || undefined,
      created_at: new Date().toISOString()
    };

    serverStorage.saveUser(user);

    // Create session token
    const tokenPayload = {
      ...user,
      exp: Math.floor(Date.now() / 1000) + (7 * 24 * 3600)
    };
    const accessToken = Buffer.from(JSON.stringify(tokenPayload)).toString("base64");

    return NextResponse.json({
      access_token: accessToken,
      token_type: "bearer",
      user
    });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || "Google authentication failed" }, { status: 500 });
  }
}
