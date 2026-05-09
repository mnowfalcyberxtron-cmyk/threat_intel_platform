import axios from "axios";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export interface CompanySummary {
  id: number;
  name: string;
  slug: string;
  official_site?: string;
  incident_count: number;
}

export interface IncidentSummary {
  id: number;
  title: string;
  summary?: string;
  threat_actor?: string;
  malware_name?: string;
  countries: string[];
  industries: string[];
  affected_products?: string;
  cve_ids: string[];
  impact?: string;
  mitre_techniques: string[];
  source_link: string;
  published_at?: string;
  source_type: string;
  company_id?: number;
  company_name?: string;
  detected_at: string;
}

export interface Indicator {
  id: number;
  type: string;
  value: string;
}

export interface CVEReference {
  id: number;
  cve_id: string;
}

export interface IncidentDetail extends IncidentSummary {
  indicators: Indicator[];
  cves: CVEReference[];
}

export interface TimelineDay {
  date: string;
  incidents: IncidentSummary[];
}

export type AIProvider = "auto" | "ollama" | "openrouter" | "groq";

export interface AIHealthResponse {
  selected_provider: AIProvider;
  active_provider: string;
  providers: Record<string, unknown>;
}

export async function fetchCompanies(): Promise<CompanySummary[]> {
  const res = await axios.get<CompanySummary[]>(`${API_BASE}/companies`);
  return res.data;
}

export async function fetchIncidents(params: Record<string, string | number | undefined> = {}): Promise<IncidentSummary[]> {
  const res = await axios.get<IncidentSummary[]>(`${API_BASE}/incidents`, {
    params,
  });
  return res.data;
}

export async function fetchIncident(id: number): Promise<IncidentDetail> {
  const res = await axios.get<IncidentDetail>(`${API_BASE}/incidents/${id}`);
  return res.data;
}

export async function fetchTimeline(days = 7): Promise<TimelineDay[]> {
  const res = await axios.get<TimelineDay[]>(`${API_BASE}/timeline`, {
    params: { days },
  });
  return res.data;
}

export async function triggerRefresh(): Promise<{ status: string; new_incidents: number }> {
  const res = await axios.post<{ status: string; new_incidents: number }>(
    `${API_BASE}/refresh`
  );
  return res.data;
}

export async function fetchAIHealth(): Promise<AIHealthResponse> {
  const res = await axios.get<AIHealthResponse>(`${API_BASE}/ai/health`);
  return res.data;
}

export async function setAIProvider(provider: AIProvider): Promise<{ selected_provider: AIProvider }> {
  const res = await axios.post<{ selected_provider: AIProvider }>(
    `${API_BASE}/ai/provider`,
    null,
    { params: { provider } }
  );
  return res.data;
}

