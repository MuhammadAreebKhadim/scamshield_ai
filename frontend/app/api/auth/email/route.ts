import { NextResponse } from "next/server";
import { serverStorage } from "@/lib/server-storage";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({}));
    const email = body.email?.trim().toLowerCase();
    const name = body.name?.trim();

    if (!email || !email.includes("@")) {
      return NextResponse.json({ error: "Valid email address is required" }, { status: 400 });
    }

    const userName = name || email.split("@")[0].replace(/[._-]/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase());
    let user = serverStorage.getUserByEmail(email);

    if (!user) {
      const hash = Math.abs(email.split("").reduce((acc: number, char: string) => acc + char.charCodeAt(0), 0) * 31);
      const userId = `usr_${hash % 1000000}`;
      user = {
        user_id: userId,
        email: email,
        name: userName,
        created_at: new Date().toISOString()
      };
      serverStorage.saveUser(user);
    }

    const tokenPayload = {
      sub: user.user_id,
      email: user.email,
      name: user.name,
      picture: user.picture,
      exp: Math.floor(Date.now() / 1000) + (7 * 24 * 3600)
    };

    const accessToken = Buffer.from(JSON.stringify(tokenPayload)).toString("base64");

    return NextResponse.json({
      access_token: accessToken,
      token_type: "bearer",
      user
    });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || "Authentication failed" }, { status: 500 });
  }
}
