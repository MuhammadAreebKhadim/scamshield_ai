function getApiBase(): string {
  if (typeof window !== "undefined") {
    const host = window.location.hostname;
    // On production (e.g. *.vercel.app, custom domains), always use relative /api
    // This eliminates Private Network Access (PNA) security popups and network fetch errors completely
    if (host !== "localhost" && host !== "127.0.0.1") {
      return "/api";
    }
    return process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000/api";
  }
  return process.env.NEXT_PUBLIC_API_URL || "/api";
}

function getAuthHeaders(): HeadersInit {
  const headers: HeadersInit = {
    "Content-Type": "application/json",
  };
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("scamshield_token");
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }
  return headers;
}

export interface Indicator {
  name: string;
  evidence: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  category?: string;
  description?: string;
  sub_signals?: string[];
}

export interface HighlightedSentence {
  text: string;
  reason: string;
  severity: string;
}

export interface ThreatIntelligence {
  urlhaus?: {
    status?: string;
    is_malicious?: boolean;
    threat?: string;
    tags?: string[];
    date_added?: string;
    url_status?: string;
  };
  virustotal?: {
    status?: string;
    malicious?: number;
    suspicious?: number;
    harmless?: number;
    undetected?: number;
    total_vendors?: number;
    summary?: string;
  };
  google_safe_browsing?: {
    status?: string;
    is_threat_found?: boolean;
    threat_types?: string[];
    summary?: string;
  };
}

export interface ScanRecord {
  scan_id: string;
  user_id?: string;
  user_email?: string;
  input_type: "url" | "message" | "job";
  input_summary: string;
  input_data: Record<string, any>;
  risk_score: number;
  risk_level: "LOW" | "CAUTION" | "SUSPICIOUS" | "HIGH";
  is_threat_confirmed: boolean;
  indicators: Indicator[];
  threat_intelligence?: ThreatIntelligence;
  ai_analysis?: {
    risk_level: string;
    risk_score: number;
    category: string;
    summary: string;
    indicators: Indicator[];
    highlighted_sentences: HighlightedSentence[];
    recommendation: string;
  };
  recommendations: string[];
  score_breakdown: Record<string, any>;
  created_at: string;
}

export interface DashboardStats {
  total_scans: number;
  high_risk_detections: number;
  suspicious_detections: number;
  caution_detections: number;
  safe_detections: number;
  recent_scans: ScanRecord[];
  threat_categories: Record<string, number>;
}

export interface UserProfile {
  user_id: string;
  email: string;
  name: string;
  picture?: string;
  created_at: string;
}

function getClientScansKey(): string {
  if (typeof window === "undefined") return "scamshield_client_scans_guest";
  try {
    const userRaw = localStorage.getItem("scamshield_user");
    if (userRaw) {
      const u = JSON.parse(userRaw);
      if (u?.email) {
        return `scamshield_client_scans_${encodeURIComponent(u.email.toLowerCase().trim())}`;
      }
      if (u?.user_id) {
        return `scamshield_client_scans_${encodeURIComponent(u.user_id.toLowerCase().trim())}`;
      }
    }
  } catch {}
  return "scamshield_client_scans_guest";
}

export function getLocalScans(): ScanRecord[] {
  if (typeof window === "undefined") return [];
  try {
    const key = getClientScansKey();
    const raw = localStorage.getItem(key);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

export function saveLocalScan(scan: ScanRecord): void {
  if (typeof window === "undefined" || !scan?.scan_id) return;
  try {
    const key = getClientScansKey();
    const current = getLocalScans();
    const updated = [scan, ...current.filter(s => s.scan_id !== scan.scan_id)].slice(0, 100);
    localStorage.setItem(key, JSON.stringify(updated));
  } catch (e) {
    console.warn("Could not save scan to localStorage", e);
  }
}

export const api = {
  async scanURL(url: string): Promise<ScanRecord> {
    const res = await fetch(`${getApiBase()}/scan/url`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: jsonBody({ url }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Failed to scan URL");
    }
    const data: ScanRecord = await res.json();
    saveLocalScan(data);
    return data;
  },

  async scanMessage(content: string, channel: string = "Email"): Promise<ScanRecord> {
    const res = await fetch(`${getApiBase()}/scan/message`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: jsonBody({ content, channel }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Failed to analyze message");
    }
    const data: ScanRecord = await res.json();
    saveLocalScan(data);
    return data;
  },

  async scanJob(payload: {
    company_name: string;
    job_title: string;
    recruiter_email?: string;
    job_description: string;
    salary_or_terms?: string;
    application_url?: string;
    recruiter_phone?: string;
    interview_platform?: string;
    is_unsolicited?: boolean;
  }): Promise<ScanRecord> {
    const res = await fetch(`${getApiBase()}/scan/job`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: jsonBody(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Failed to verify job offer");
    }
    const data: ScanRecord = await res.json();
    saveLocalScan(data);
    return data;
  },

  async getHistory(params?: {
    limit?: number;
    type?: string;
    risk_level?: string;
  }): Promise<ScanRecord[]> {
    const q = new URLSearchParams();
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.type) q.set("type", params.type);
    if (params?.risk_level) q.set("risk_level", params.risk_level);

    let serverScans: ScanRecord[] = [];
    try {
      const res = await fetch(`${getApiBase()}/scan/history?${q.toString()}`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        serverScans = await res.json();
      }
    } catch {
      // server fetch error, fallback to client
    }

    // Merge server scans and client scans, deduplicated by scan_id
    const localScans = getLocalScans();
    const map = new Map<string, ScanRecord>();
    for (const s of localScans) {
      if (s?.scan_id) map.set(s.scan_id, s);
    }
    for (const s of serverScans) {
      if (s?.scan_id) map.set(s.scan_id, s);
    }

    let merged = Array.from(map.values()).sort(
      (a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()
    );

    if (params?.type) {
      merged = merged.filter(s => s.input_type?.toLowerCase() === params.type?.toLowerCase());
    }
    if (params?.risk_level) {
      merged = merged.filter(s => s.risk_level?.toUpperCase() === params.risk_level?.toUpperCase());
    }
    if (params?.limit) {
      merged = merged.slice(0, params.limit);
    }
    return merged;
  },

  async getScan(scanId: string): Promise<ScanRecord> {
    try {
      const res = await fetch(`${getApiBase()}/scan/${scanId}`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        saveLocalScan(data);
        return data;
      }
    } catch {
      // fallback
    }

    const local = getLocalScans().find(s => s.scan_id === scanId);
    if (local) return local;

    throw new Error("Scan report not found");
  },

  async getDashboardStats(): Promise<DashboardStats> {
    let stats: DashboardStats | null = null;
    try {
      const res = await fetch(`${getApiBase()}/dashboard/stats`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        stats = await res.json();
      }
    } catch {
      // fallback
    }

    const localScans = getLocalScans();
    if (!stats || (stats.total_scans === 0 && localScans.length > 0)) {
      const total = localScans.length;
      const high = localScans.filter(s => s.risk_level === "HIGH").length;
      const suspicious = localScans.filter(s => s.risk_level === "SUSPICIOUS").length;
      const caution = localScans.filter(s => s.risk_level === "CAUTION").length;
      const safe = localScans.filter(s => s.risk_level === "LOW").length;

      return {
        total_scans: total,
        high_risk_detections: high,
        suspicious_detections: suspicious,
        caution_detections: caution,
        safe_detections: safe,
        recent_scans: localScans.slice(0, 10),
        threat_categories: {
          "Phishing & Suspicious URLs": localScans.filter(s => s.input_type === "url").length,
          "Email & Message Forensics": localScans.filter(s => s.input_type === "message").length,
          "Recruitment Verifications": localScans.filter(s => s.input_type === "job").length,
          "High-Risk Critical Alerts": high,
          "Verified Safe": safe
        }
      };
    }

    // Merge recent scans with local scans if any are missing
    const map = new Map<string, ScanRecord>();
    for (const s of localScans) {
      if (s?.scan_id) map.set(s.scan_id, s);
    }
    for (const s of (stats.recent_scans || [])) {
      if (s?.scan_id) map.set(s.scan_id, s);
    }
    const all = Array.from(map.values()).sort(
      (a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()
    );

    stats.total_scans = Math.max(stats.total_scans, all.length);
    stats.high_risk_detections = all.filter(s => s.risk_level === "HIGH").length;
    stats.suspicious_detections = all.filter(s => s.risk_level === "SUSPICIOUS").length;
    stats.caution_detections = all.filter(s => s.risk_level === "CAUTION").length;
    stats.safe_detections = all.filter(s => s.risk_level === "LOW").length;
    stats.recent_scans = all.slice(0, 10);

    return stats;
  },

  async googleAuth(credential: string): Promise<{ access_token: string; user: UserProfile }> {
    const res = await fetch(`${getApiBase()}/auth/google`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: jsonBody({ credential }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Google authentication failed");
    }
    const data = await res.json();
    if (typeof window !== "undefined") {
      localStorage.setItem("scamshield_token", data.access_token);
      localStorage.setItem("scamshield_user", JSON.stringify(data.user));
    }
    return data;
  },

  async emailAuth(email: string, name?: string): Promise<{ access_token: string; user: UserProfile }> {
    const res = await fetch(`${getApiBase()}/auth/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: jsonBody({ email, name }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Authentication failed");
    }
    const data = await res.json();
    if (typeof window !== "undefined") {
      localStorage.setItem("scamshield_token", data.access_token);
      localStorage.setItem("scamshield_user", JSON.stringify(data.user));
    }
    return data;
  },

  async getMe(): Promise<UserProfile | null> {
    const res = await fetch(`${getApiBase()}/auth/me`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) return null;
    return res.json();
  },
};

function jsonBody(obj: any): string {
  return JSON.stringify(obj);
}
