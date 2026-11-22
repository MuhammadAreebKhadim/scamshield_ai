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
    return res.json();
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
    return res.json();
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
    return res.json();
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

    const res = await fetch(`${getApiBase()}/scan/history?${q.toString()}`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error("Failed to load scan history");
    return res.json();
  },

  async getScan(scanId: string): Promise<ScanRecord> {
    const res = await fetch(`${getApiBase()}/scan/${scanId}`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error("Scan report not found");
    return res.json();
  },

  async getDashboardStats(): Promise<DashboardStats> {
    const res = await fetch(`${getApiBase()}/dashboard/stats`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error("Failed to load dashboard metrics");
    return res.json();
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
