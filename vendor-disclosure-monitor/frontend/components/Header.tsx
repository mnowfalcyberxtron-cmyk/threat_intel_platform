import React from "react";
import { AIProvider } from "../lib/api";

interface HeaderProps {
  search: string;
  onSearchChange: (value: string) => void;
  onRefresh: () => void;
  lastUpdated?: string;
  selectedProvider?: AIProvider;
  onProviderChange?: (provider: AIProvider) => void;
}

export const Header: React.FC<HeaderProps> = ({
  search,
  onSearchChange,
  onRefresh,
  lastUpdated,
  selectedProvider,
  onProviderChange,
}) => {
  return (
    <div className="flex items-center justify-between px-6 py-3 border-b border-slate-800 bg-slate-900/80 backdrop-blur">
      <div className="flex-1 max-w-xl">
        <input
          type="text"
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search advisories, incidents, CVEs, vendors..."
          className="w-full rounded-md bg-slate-900 border border-slate-700 px-3 py-1.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
        />
      </div>
      <div className="flex items-center gap-3 ml-4">
        {onProviderChange && (
          <select
            value={selectedProvider ?? "auto"}
            onChange={(e) => onProviderChange(e.target.value as AIProvider)}
            className="rounded-md bg-slate-900 border border-slate-700 px-2 py-1.5 text-xs text-slate-100"
          >
            <option value="auto">AI: Auto</option>
            <option value="ollama">AI: Ollama</option>
            <option value="openrouter">AI: OpenRouter</option>
            <option value="groq">AI: Groq</option>
          </select>
        )}
        {lastUpdated && (
          <span className="text-[11px] text-slate-400">
            Last updated: {lastUpdated}
          </span>
        )}
        <button
          type="button"
          onClick={onRefresh}
          className="inline-flex items-center rounded-md bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 transition-colors"
        >
          Refresh now
        </button>
      </div>
    </div>
  );
};

