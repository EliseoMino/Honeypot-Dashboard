import type { ReactNode } from "react";
import { useLocation } from "react-router-dom";

type ExportKind = "events" | "alerts";

export function ExportLinks({ kind }: { kind: ExportKind }): ReactNode {
  const location = useLocation();
  const query = location.search;
  return (
    <div className="export-links" aria-label={`Exportar ${kind === "events" ? "eventos" : "alertas"}`}>
      <a className="button button--ghost" href={`/api/v1/exports/${kind}.csv${query}`} download>
        CSV
      </a>
      <a className="button button--ghost" href={`/api/v1/exports/${kind}.json${query}`} download>
        JSON
      </a>
      {kind === "events" ? (
        <a className="button button--ghost" href={`/api/v1/exports/report.json${query}`} download>
          Informe JSON
        </a>
      ) : null}
    </div>
  );
}
