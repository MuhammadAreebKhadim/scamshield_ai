import { NextResponse } from "next/server";
import { getUserFromAuthHeader } from "@/lib/server-auth";
import { serverStorage } from "@/lib/server-storage";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  try {
    const authUser = getUserFromAuthHeader(req);
    if (!authUser || !authUser.email) {
      return NextResponse.json(null);
    }

    const dbUser = serverStorage.getUserByEmail(authUser.email);
    if (dbUser) {
      return NextResponse.json(dbUser);
    }

    return NextResponse.json({
      user_id: authUser.user_id || "usr_anonymous",
      email: authUser.email,
      name: authUser.name || authUser.email.split("@")[0],
      created_at: new Date().toISOString()
    });
  } catch {
    return NextResponse.json(null);
  }
}
