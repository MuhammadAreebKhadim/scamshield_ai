import { NextResponse } from "next/server";
import { getUserFromAuthHeader } from "@/lib/server-auth";
import { serverStorage } from "@/lib/server-storage";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  try {
    const authUser = getUserFromAuthHeader(req);
    const userId = authUser?.user_id;
    const email = authUser?.email;

    const stats = serverStorage.getDashboardStats(userId, email);
    return NextResponse.json(stats);
  } catch (err: any) {
    return NextResponse.json({ error: err.message || "Failed to get stats" }, { status: 500 });
  }
}
