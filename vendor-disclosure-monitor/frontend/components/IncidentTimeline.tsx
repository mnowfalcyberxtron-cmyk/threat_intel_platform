import { IncidentSummary, TimelineDay } from "../lib/api";
import { IncidentList } from "./IncidentList";

interface Props {
  timeline: TimelineDay[];
}

export const IncidentTimeline: React.FC<Props> = ({ timeline }) => {
  return (
    <div className="flex-1 overflow-y-auto">
      {timeline.map((day) => (
        <section key={day.date} className="border-b border-slate-900">
          <div className="sticky top-0 z-10 bg-slate-950/90 backdrop-blur border-b border-slate-900 px-6 py-1.5">
            <span className="text-[11px] font-semibold text-slate-300">
              {new Date(day.date).toLocaleDateString(undefined, {
                weekday: "short",
                month: "short",
                day: "numeric",
                year: "numeric",
              })}
            </span>
          </div>
          <IncidentList incidents={day.incidents as IncidentSummary[]} />
        </section>
      ))}
      {timeline.length === 0 && (
        <div className="px-6 py-8 text-sm text-slate-400">
          No incidents have been ingested yet. Try running a manual refresh.
        </div>
      )}
    </div>
  );
};

