import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import {
  CompanySummary,
  IncidentSummary,
  fetchCompanies,
  fetchIncidents,
  triggerRefresh,
} from "../../lib/api";
import { Layout } from "../../components/Layout";
import { Header } from "../../components/Header";
import { IncidentFilters } from "../../components/IncidentFilters";
import { IncidentList } from "../../components/IncidentList";

export default function CompanyPage() {
  const router = useRouter();
  const id =
    typeof router.query.id === "string" ? Number(router.query.id) : undefined;

  const [companies, setCompanies] = useState<CompanySummary[]>([]);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [search, setSearch] = useState("");
  const [sourceType, setSourceType] = useState("");
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | undefined>();

  useEffect(() => {
    async function load() {
      if (!id) return;
      setLoading(true);
      try {
        const [companiesData, incidentsData] = await Promise.all([
          fetchCompanies(),
          fetchIncidents({
            company_id: id,
            source_type: sourceType || undefined,
            q: search || undefined,
          }),
        ]);
        setCompanies(companiesData);
        setIncidents(incidentsData);
        setLastUpdated(new Date().toLocaleTimeString());
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id, search, sourceType]);

  const reload = async () => {
    if (!id) return;
    setLoading(true);
    try {
      await fetchIncidents({
        company_id: id,
        source_type: sourceType || undefined,
        q: search || undefined,
      }).then(setIncidents);
      setLastUpdated(new Date().toLocaleTimeString());
    } finally {
      setLoading(false);
    }
  };

  const company = companies.find((c) => c.id === id);

  return (
    <Layout companies={companies}>
      <Header
        search={search}
        onSearchChange={setSearch}
        onRefresh={async () => {
          await triggerRefresh();
          await reload();
        }}
        lastUpdated={lastUpdated}
      />
      <IncidentFilters
        sourceType={sourceType}
        onSourceTypeChange={setSourceType}
      />
      <div className="px-6 py-2 border-b border-slate-800 bg-slate-950/80">
        <h2 className="text-sm font-semibold text-slate-100">
          {company ? company.name : "Company incidents"}
        </h2>
      </div>
      <div className="flex-1 overflow-y-auto">
        <IncidentList incidents={incidents} />
      </div>
      {loading && (
        <div className="absolute bottom-4 right-6 text-xs text-slate-400 bg-slate-900/80 px-3 py-1.5 rounded-md border border-slate-700">
          Loading company incidents…
        </div>
      )}
    </Layout>
  );
}

