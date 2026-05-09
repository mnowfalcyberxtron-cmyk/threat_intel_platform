import Link from "next/link";
import { IncidentSummary } from "../lib/api";

interface Props {
  incidents: IncidentSummary[];
}

export const IncidentList: React.FC<Props> = ({ incidents }) => {
  return (
    <div className="divide-y divide-slate-800">
      {incidents.map((inc) => (
        <Link
          key={inc.id}
          href={`/incident/${inc.id}`}
          className="block px-6 py-3 hover:bg-slate-900/60 transition-colors"
        >
          <div className="flex items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-slate-50">
                  {inc.title}
                </span>
                <span
                  className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                    inc.source_type === "OFFICIAL_VENDOR_DISCLOSURE"
                      ? "bg-emerald-900/60 text-emerald-300"
                      : "bg-amber-900/60 text-amber-300"
                  }`}
                >
                  {inc.source_type === "OFFICIAL_VENDOR_DISCLOSURE"
                    ? "Official vendor"
                    : "External intel"}
                </span>
                {inc.company_name && (
                  <span className="text-[11px] text-slate-400">
                    {inc.company_name}
                  </span>
                )}
              </div>
              {inc.summary && (
                <p className="mt-1 text-xs text-slate-300 line-clamp-2">
                  {inc.summary}
                </p>
              )}
              <div className="mt-1 flex flex-wrap gap-1.5">
                {inc.cve_ids?.slice(0, 3).map((cve) => (
                  <span
                    key={cve}
                    className="inline-flex items-center rounded-full border border-sky-700/60 bg-sky-900/40 px-1.5 py-0.5 text-[10px] text-sky-200"
                  >
                    {cve}
                  </span>
                ))}
                {inc.mitre_techniques?.slice(0, 3).map((tech) => (
                  <span
                    key={tech}
                    className="inline-flex items-center rounded-full border border-violet-700/60 bg-violet-900/40 px-1.5 py-0.5 text-[10px] text-violet-200"
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </div>
            <div className="flex flex-col items-end gap-1">
              {inc.published_at && (
                <span className="text-[11px] text-slate-400">
                  {new Date(inc.published_at).toLocaleString()}
                </span>
              )}
              <span className="text-[10px] text-slate-500">
                Detected{" "}
                {new Date(inc.detected_at).toLocaleTimeString(undefined, {
                  hour: "2-digit",
                  minute: "2-digit",
                })}
              </span>
            </div>
          </div>
        </Link>
      ))}
      {incidents.length === 0 && (
        <div className="px-6 py-8 text-sm text-slate-400">
          No incidents match the current filters.
        </div>
      )}
    </div>
  );
};

