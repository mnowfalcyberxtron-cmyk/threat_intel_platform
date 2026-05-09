import React from "react";

interface IncidentFiltersProps {
  sourceType: string;
  onSourceTypeChange: (value: string) => void;
}

export const IncidentFilters: React.FC<IncidentFiltersProps> = ({
  sourceType,
  onSourceTypeChange,
}) => {
  return (
    <div className="flex items-center gap-3 px-6 py-2 border-b border-slate-800 bg-slate-950/80">
      <div className="text-[11px] text-slate-400 uppercase tracking-wide">
        Source type
      </div>
      <div className="inline-flex rounded-full bg-slate-900 border border-slate-700 text-xs overflow-hidden">
        <button
          type="button"
          onClick={() => onSourceTypeChange("")}
          className={`px-3 py-1 ${
            sourceType === "" ? "bg-sky-600 text-white" : "text-slate-200"
          }`}
        >
          All
        </button>
        <button
          type="button"
          onClick={() =>
            onSourceTypeChange("OFFICIAL_VENDOR_DISCLOSURE")
          }
          className={`px-3 py-1 border-l border-slate-700 ${
            sourceType === "OFFICIAL_VENDOR_DISCLOSURE"
              ? "bg-sky-600 text-white"
              : "text-slate-200"
          }`}
        >
          Official vendor
        </button>
        <button
          type="button"
          onClick={() =>
            onSourceTypeChange("EXTERNAL_INTELLIGENCE_REPORT")
          }
          className={`px-3 py-1 border-l border-slate-700 ${
            sourceType === "EXTERNAL_INTELLIGENCE_REPORT"
              ? "bg-sky-600 text-white"
              : "text-slate-200"
          }`}
        >
          External intel
        </button>
      </div>
    </div>
  );
};

