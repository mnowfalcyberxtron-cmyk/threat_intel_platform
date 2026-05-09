import { useEffect, useState } from "react";
import {
  AIProvider,
  CompanySummary,
  IncidentSummary,
  TimelineDay,
  fetchAIHealth,
  fetchCompanies,
  setAIProvider,
  fetchTimeline,
  triggerRefresh,
} from "../lib/api";
import { Layout } from "../components/Layout";
import { Header } from "../components/Header";
import { IncidentFilters } from "../components/IncidentFilters";
import { IncidentTimeline } from "../components/IncidentTimeline";

export default function HomePage() {
  const [companies, setCompanies] = useState<CompanySummary[]>([]);
  const [timeline, setTimeline] = useState<TimelineDay[]>([]);
  const [search, setSearch] = useState("");
  const [sourceType, setSourceType] = useState("");
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | undefined>();
  const [selectedProvider, setSelectedProvider] = useState<AIProvider>("auto");

  async function loadData() {
    setLoading(true);
    try {
      const [companiesData, timelineData] = await Promise.all([
        fetchCompanies(),
        fetchTimeline(7),
      ]);
      setCompanies(companiesData);
      // Filter by source type client-side for now
      const filteredTimeline =
        sourceType === ""
          ? timelineData
          : timelineData.map((day) => ({
              ...day,
              incidents: day.incidents.filter(
                (inc: IncidentSummary) => inc.source_type === sourceType
              ),
            }));
      const searchedTimeline =
        search.trim() === ""
          ? filteredTimeline
          : filteredTimeline.map((day) => ({
              ...day,
              incidents: day.incidents.filter((inc) => {
                const q = search.toLowerCase();
                return (
                  inc.title.toLowerCase().includes(q) ||
                  (inc.summary ?? "").toLowerCase().includes(q) ||
                  (inc.company_name ?? "").toLowerCase().includes(q) ||
                  inc.cve_ids?.some((c) => c.toLowerCase().includes(q))
                );
              }),
            }));
      setTimeline(searchedTimeline);
      setLastUpdated(new Date().toLocaleTimeString());
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 60_000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceType, search]);

  useEffect(() => {
    fetchAIHealth()
      .then((res) => setSelectedProvider(res.selected_provider))
      .catch(() => setSelectedProvider("auto"));
  }, []);

  const handleRefresh = async () => {
    setLoading(true);
    try {
      await triggerRefresh();
      await loadData();
    } finally {
      setLoading(false);
    }
  };

  return (
    <Layout companies={companies}>
      <Header
        search={search}
        onSearchChange={setSearch}
        onRefresh={handleRefresh}
        lastUpdated={lastUpdated}
        selectedProvider={selectedProvider}
        onProviderChange={async (provider) => {
          setSelectedProvider(provider);
          await setAIProvider(provider);
        }}
      />
      <IncidentFilters
        sourceType={sourceType}
        onSourceTypeChange={setSourceType}
      />
      <IncidentTimeline timeline={timeline} />
      {loading && (
        <div className="absolute bottom-4 right-6 text-xs text-slate-400 bg-slate-900/80 px-3 py-1.5 rounded-md border border-slate-700">
          Syncing incidents…
        </div>
      )}
    </Layout>
  );
}

