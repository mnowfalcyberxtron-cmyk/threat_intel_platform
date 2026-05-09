import Link from "next/link";
import { useRouter } from "next/router";
import { CompanySummary } from "../lib/api";

interface Props {
  companies: CompanySummary[];
}

export const CompanySidebar: React.FC<Props> = ({ companies }) => {
  const router = useRouter();
  const currentCompanyId =
    typeof router.query.id === "string" ? Number(router.query.id) : undefined;

  return (
    <nav className="py-3 overflow-y-auto h-[calc(100vh-56px)]">
      <Link
        href="/"
        className={`flex items-center px-4 py-2 text-sm font-medium hover:bg-slate-800 ${
          !currentCompanyId && router.pathname === "/"
            ? "bg-slate-800 text-sky-300"
            : "text-slate-200"
        }`}
      >
        All Vendors
      </Link>
      <div className="mt-2 px-4 text-xs uppercase tracking-wide text-slate-400">
        Vendors
      </div>
      <ul className="mt-1 space-y-0.5">
        {companies.map((c) => {
          const active = currentCompanyId === c.id;
          return (
            <li key={c.id}>
              <Link
                href={`/company/${c.id}`}
                className={`flex items-center justify-between px-4 py-1.5 text-xs hover:bg-slate-800 ${
                  active ? "bg-slate-800 text-sky-300" : "text-slate-200"
                }`}
              >
                <span className="truncate">{c.name}</span>
                <span className="ml-2 inline-flex items-center justify-center rounded-full bg-slate-800 text-[10px] px-1.5 py-0.5 text-slate-300">
                  {c.incident_count}
                </span>
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
};

