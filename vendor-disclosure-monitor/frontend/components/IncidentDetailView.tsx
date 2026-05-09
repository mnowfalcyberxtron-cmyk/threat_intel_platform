import Link from "next/link";
import { IncidentDetail } from "../lib/api";

interface Props {
  incident: IncidentDetail;
}

export const IncidentDetailView: React.FC<Props> = ({ incident }) => {
  const ips = incident.indicators.filter((i) => i.type === "IP");
  const domains = incident.indicators.filter((i) => i.type === "DOMAIN");
  const hashes = incident.indicators.filter((i) => i.type === "HASH");
  const urls = incident.indicators.filter((i) => i.type === "URL");

  return (
    <div className="flex-1 overflow-y-auto px-8 py-6 space-y-6">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold text-slate-50">
            {incident.title}
          </h1>
          <span
            className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-[11px] font-semibold ${
              incident.source_type === "OFFICIAL_VENDOR_DISCLOSURE"
                ? "bg-emerald-900/60 text-emerald-300"
                : "bg-amber-900/60 text-amber-300"
            }`}
          >
            {incident.source_type === "OFFICIAL_VENDOR_DISCLOSURE"
              ? "Official vendor disclosure"
              : "External intelligence report"}
          </span>
        </div>
        <div className="mt-2 text-sm text-slate-300 whitespace-pre-line">
          {incident.summary}
        </div>
        <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-slate-400">
          {incident.company_name && (
            <span>Vendor: {incident.company_name}</span>
          )}
          {incident.published_at && (
            <span>
              Published:{" "}
              {new Date(incident.published_at).toLocaleString(undefined, {
                dateStyle: "medium",
                timeStyle: "short",
              })}
            </span>
          )}
          <span>
            Detected:{" "}
            {new Date(incident.detected_at).toLocaleString(undefined, {
              dateStyle: "medium",
              timeStyle: "short",
            })}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="space-y-3">
          <h2 className="text-xs font-semibold text-slate-300 uppercase tracking-wide">
            CVEs & techniques
          </h2>
          <div className="flex flex-wrap gap-1.5">
            {incident.cve_ids?.map((cve) => (
              <span
                key={cve}
                className="inline-flex items-center rounded-full border border-sky-700/60 bg-sky-900/40 px-1.5 py-0.5 text-[10px] text-sky-200"
              >
                {cve}
              </span>
            ))}
            {incident.mitre_techniques?.map((tech) => (
              <span
                key={tech}
                className="inline-flex items-center rounded-full border border-violet-700/60 bg-violet-900/40 px-1.5 py-0.5 text-[10px] text-violet-200"
              >
                {tech}
              </span>
            ))}
            {incident.cve_ids.length === 0 &&
              incident.mitre_techniques.length === 0 && (
                <p className="text-xs text-slate-500">
                  No CVEs or MITRE techniques extracted.
                </p>
              )}
          </div>
        </div>

        <div className="space-y-3">
          <h2 className="text-xs font-semibold text-slate-300 uppercase tracking-wide">
            Affected products
          </h2>
          <div className="text-xs text-slate-300 whitespace-pre-line">
            {incident.affected_products || "Not specified."}
          </div>
        </div>

        <div className="space-y-3">
          <h2 className="text-xs font-semibold text-slate-300 uppercase tracking-wide">
            Source
          </h2>
          <div className="text-xs text-slate-300">
            <div>
              <span className="text-slate-400">Source URL: </span>
              <Link
                href={incident.source_link}
                target="_blank"
                className="text-sky-400 hover:text-sky-300 break-all"
              >
                {incident.source_link}
              </Link>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div>
          <h2 className="text-xs font-semibold text-slate-300 uppercase tracking-wide mb-2">
            IP indicators
          </h2>
          {ips.length === 0 ? (
            <p className="text-xs text-slate-500">None extracted.</p>
          ) : (
            <ul className="text-xs text-slate-300 space-y-1">
              {ips.map((i) => (
                <li key={i.id}>{i.value}</li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <h2 className="text-xs font-semibold text-slate-300 uppercase tracking-wide mb-2">
            Domain indicators
          </h2>
          {domains.length === 0 ? (
            <p className="text-xs text-slate-500">None extracted.</p>
          ) : (
            <ul className="text-xs text-slate-300 space-y-1">
              {domains.map((i) => (
                <li key={i.id}>{i.value}</li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <h2 className="text-xs font-semibold text-slate-300 uppercase tracking-wide mb-2">
            URL indicators
          </h2>
          {urls.length === 0 ? (
            <p className="text-xs text-slate-500">None extracted.</p>
          ) : (
            <ul className="text-xs text-slate-300 space-y-1 break-all">
              {urls.map((i) => (
                <li key={i.id}>{i.value}</li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <h2 className="text-xs font-semibold text-slate-300 uppercase tracking-wide mb-2">
            File hashes
          </h2>
          {hashes.length === 0 ? (
            <p className="text-xs text-slate-500">None extracted.</p>
          ) : (
            <ul className="text-xs text-slate-300 space-y-1">
              {hashes.map((i) => (
                <li key={i.id}>{i.value}</li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
};

