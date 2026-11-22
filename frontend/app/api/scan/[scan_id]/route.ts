import { NextResponse } from "next/server";
import { serverStorage } from "@/lib/server-storage";

export const dynamic = "force-dynamic";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ scan_id: string }> }
) {
  try {
    const { scan_id } = await params;
    const scan = serverStorage.getScan(scan_id);

    if (!scan) {
      return NextResponse.json({ error: `Scan report '${scan_id}' not found` }, { status: 404 });
    }

    return NextResponse.json(scan);
  } catch (err: any) {
    return NextResponse.json({ error: err.message || "Failed to load scan" }, { status: 500 });
  }
}
