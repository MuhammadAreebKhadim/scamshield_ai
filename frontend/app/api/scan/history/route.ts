import { NextResponse } from "next/server";
import { getUserFromAuthHeader } from "@/lib/server-auth";
import { serverStorage } from "@/lib/server-storage";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  try {
    const { searchParams } = new URL(req.url);
    const limit = parseInt(searchParams.get("limit") || "50", 10);
    const inputType = searchParams.get("type")?.toLowerCase();
    const riskLevel = searchParams.get("risk_level")?.toUpperCase();

    const authUser = getUserFromAuthHeader(req);
    const userId = authUser?.user_id;
    const email = authUser?.email;

    let scans = serverStorage.getRecentScans(Math.min(limit, 100), userId, email);

    if (inputType) {
      scans = scans.filter(s => s.input_type.toLowerCase() === inputType);
    }
    if (riskLevel) {
      scans = scans.filter(s => s.risk_level.toUpperCase() === riskLevel);
    }

    return NextResponse.json(scans);
  } catch (err: any) {
    return NextResponse.json({ error: err.message || "Failed to load history" }, { status: 500 });
  }
}
