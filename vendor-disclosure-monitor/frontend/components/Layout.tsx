import React from "react";
import { CompanySummary } from "../lib/api";
import { CompanySidebar } from "./CompanySidebar";

interface LayoutProps {
  companies: CompanySummary[];
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({ companies, children }) => {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      <aside className="w-64 border-r border-slate-800 bg-slate-900/70">
        <div className="px-4 py-4 border-b border-slate-800">
          <h1 className="text-lg font-semibold tracking-tight">
            Vendor Disclosure Monitor
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Official advisories & external intel
          </p>
        </div>
        <CompanySidebar companies={companies} />
      </aside>
      <main className="flex-1 flex flex-col">{children}</main>
    </div>
  );
};

