import fs from "fs";
import path from "path";
import os from "os";

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

export interface UserProfile {
  user_id: string;
  email: string;
  name: string;
  picture?: string;
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

const STORAGE_FILE = path.join(os.tmpdir(), "scamshield_store.json");

interface StoreState {
  users: Record<string, UserProfile>;
  scans: ScanRecord[];
}

let inMemoryStore: StoreState = {
  users: {},
  scans: []
};

function loadStore(): StoreState {
  try {
    if (fs.existsSync(STORAGE_FILE)) {
      const data = fs.readFileSync(STORAGE_FILE, "utf-8");
      inMemoryStore = JSON.parse(data);
    }
  } catch (e) {
    // ignore
  }
  return inMemoryStore;
}

function persistStore(): void {
  try {
    fs.writeFileSync(STORAGE_FILE, JSON.stringify(inMemoryStore, null, 2), "utf-8");
  } catch (e) {
    // ignore
  }
}

export const serverStorage = {
  saveScan(scan: ScanRecord): ScanRecord {
    loadStore();
    // Prepend new scan
    inMemoryStore.scans = [scan, ...inMemoryStore.scans.filter(s => s.scan_id !== scan.scan_id)];
    persistStore();
    return scan;
  },

  getScan(scanId: string): ScanRecord | null {
    loadStore();
    return inMemoryStore.scans.find(s => s.scan_id === scanId) || null;
  },

  getRecentScans(limit: number = 50, userId?: string, email?: string): ScanRecord[] {
    loadStore();
    const normalizedUserId = (userId || "").toLowerCase();
    const normalizedEmail = (email || "").toLowerCase();

    let list = inMemoryStore.scans;
    if (normalizedUserId && normalizedUserId !== "anonymous") {
      list = list.filter(s => {
        const sUser = (s.user_id || "").toLowerCase();
        const sEmail = (s.user_email || "").toLowerCase();
        return sUser === normalizedUserId || sEmail === normalizedEmail || sUser === normalizedEmail;
      });
    } else {
      list = list.filter(s => !s.user_id || s.user_id === "anonymous");
    }
    return list.slice(0, limit);
  },

  getDashboardStats(userId?: string, email?: string): DashboardStats {
    loadStore();
    const isUserLogged = Boolean(userId && userId !== "anonymous");
    const normalizedUserId = (userId || "").toLowerCase();
    const normalizedEmail = (email || "").toLowerCase();

    const userScans = isUserLogged
      ? inMemoryStore.scans.filter(s => {
          const sUser = (s.user_id || "").toLowerCase();
          const sEmail = (s.user_email || "").toLowerCase();
          return sUser === normalizedUserId || sEmail === normalizedEmail || sUser === normalizedEmail;
        })
      : inMemoryStore.scans.filter(s => !s.user_id || s.user_id === "anonymous");

    const total = userScans.length;
    const high = userScans.filter(s => s.risk_level === "HIGH").length;
    const suspicious = userScans.filter(s => s.risk_level === "SUSPICIOUS").length;
    const caution = userScans.filter(s => s.risk_level === "CAUTION").length;
    const safe = userScans.filter(s => s.risk_level === "LOW").length;

    const urlCount = userScans.filter(s => s.input_type === "url").length;
    const msgCount = userScans.filter(s => s.input_type === "message").length;
    const jobCount = userScans.filter(s => s.input_type === "job").length;

    return {
      total_scans: total,
      high_risk_detections: high,
      suspicious_detections: suspicious,
      caution_detections: caution,
      safe_detections: safe,
      recent_scans: userScans.slice(0, 10),
      threat_categories: {
        "Phishing & Suspicious URLs": urlCount,
        "Email & Message Forensics": msgCount,
        "Recruitment Verifications": jobCount,
        "High-Risk Critical Alerts": high,
        "Verified Safe": safe
      }
    };
  },

  saveUser(user: UserProfile): UserProfile {
    loadStore();
    inMemoryStore.users[user.email.toLowerCase()] = user;
    persistStore();
    return user;
  },

  getUserByEmail(email: string): UserProfile | null {
    loadStore();
    return inMemoryStore.users[email.toLowerCase()] || null;
  }
};
