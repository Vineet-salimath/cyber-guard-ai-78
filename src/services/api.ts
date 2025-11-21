// API Service for Dashboard - Backend Communication

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';

export interface ScanResponse {
  success: boolean;
  message?: string;
  url?: string;
  risk?: string;
  score?: number;
  threat_names?: string[];
  ml_prediction?: string;
  stats?: {
    total_scans: number;
    benign_count: number;
    suspicious_count: number;
    malicious_count: number;
    benign_percentage: number;
    suspicious_percentage: number;
    malicious_percentage: number;
    last_updated: string;
  };
}

export interface ScanStats {
  total_scans: number;
  benign_count: number;
  suspicious_count: number;
  malicious_count: number;
  benign_percentage: number;
  suspicious_percentage: number;
  malicious_percentage: number;
  last_updated: string;
}

class APIService {
  private baseURL: string;

  constructor() {
    this.baseURL = BACKEND_URL;
    console.log('📡 [API] Initialized with backend URL:', this.baseURL);
  }

  async testConnection(): Promise<boolean> {
    try {
      console.log('🔌 [API] Testing connection to backend...');
      const response = await fetch(`${this.baseURL}/health`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Health check failed with status ${response.status}`);
      }

      const data = await response.json();
      console.log('✅ [API] Backend is healthy:', data);
      return true;
    } catch (error) {
      console.error('❌ [API] Connection test failed:', error);
      return false;
    }
  }

  async scanURL(url: string, timestamp?: number, source?: string): Promise<ScanResponse> {
    try {
      console.log('🔍 [API] Scanning URL:', url);
      const response = await fetch(`${this.baseURL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Origin': window.location.origin,
        },
        body: JSON.stringify({
          url,
          timestamp: timestamp || Date.now(),
          source: source || 'dashboard',
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('❌ [API] Scan failed:', response.status, errorText);
        throw new Error(`Scan failed: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('✅ [API] Scan completed:', data);
      return data;
    } catch (error) {
      console.error('❌ [API] Scan error:', error);
      throw error;
    }
  }

  async getScanStats(): Promise<ScanStats> {
    try {
      console.log('📊 [API] Fetching scan statistics...');
      const response = await fetch(`${this.baseURL}/api/scan/stats`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('❌ [API] Stats fetch failed:', response.status, errorText);
        throw new Error(`Stats fetch failed: ${response.status}`);
      }

      const data = await response.json();
      console.log('✅ [API] Stats loaded:', data);
      return data;
    } catch (error) {
      console.error('❌ [API] Stats error:', error);
      throw error;
    }
  }

  async getScanHistory(limit: number = 100): Promise<any[]> {
    try {
      console.log('📋 [API] Fetching scan history...');
      const response = await fetch(`${this.baseURL}/api/scan/history?limit=${limit}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`History fetch failed: ${response.status}`);
      }

      const data = await response.json();
      console.log('✅ [API] History loaded:', data.length, 'scans');
      return data;
    } catch (error) {
      console.error('❌ [API] History error:', error);
      throw error;
    }
  }

  getWebSocketURL(): string {
    return this.baseURL;
  }
}

export const apiService = new APIService();
export default apiService;
