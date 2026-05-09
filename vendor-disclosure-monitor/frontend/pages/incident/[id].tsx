import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import {
  CompanySummary,
  IncidentDetail,
  fetchCompanies,
  fetchIncident,
} from "../../lib/api";
import { Layout } from "../../components/Layout";
import { IncidentDetailView } from "../../components/IncidentDetailView";

export default function IncidentPage() {
  const router = useRouter();
  const id =
    typeof router.query.id === "string" ? Number(router.query.id) : undefined;

  const [companies, setCompanies] = useState<CompanySummary[]>([]);
  const [incident, setIncident] = useState<IncidentDetail | null>(null);

  useEffect(() => {
    async function load() {
      if (!id) return;
      const [companiesData, incidentData] = await Promise.all([
        fetchCompanies(),
        fetchIncident(id),
      ]);
      setCompanies(companiesData);
      setIncident(incidentData);
    }
    load();
  }, [id]);

  return (
    <Layout companies={companies}>
      {incident ? (
        <IncidentDetailView incident={incident} />
      ) : (
        <div className="flex-1 flex items-center justify-center text-sm text-slate-400">
          Loading incident…
        </div>
      )}
    </Layout>
  );
}

