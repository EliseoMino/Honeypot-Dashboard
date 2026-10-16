import type { ReactNode } from "react";

import { fetchDetectionRules } from "../api/client";
import { ErrorBanner, Loading } from "../components/Feedback";
import { useResource } from "../hooks/useResource";

export function RulesPage(): ReactNode {
  const resource = useResource((signal) => fetchDetectionRules(signal), []);
  if (resource.error !== null) return <div className="page"><ErrorBanner message={resource.error} onRetry={resource.reload} /></div>;
  if (resource.data === null) return <Loading label="Consultando reglas" />;
  if (!resource.data.available) return <div className="page"><h1>Reglas de detección</h1><ErrorBanner message={resource.data.error ?? "La configuración de reglas no está disponible."} onRetry={resource.reload} /></div>;
  return (
    <div className="page">
      <header className="page__header"><div><h1>Reglas de detección</h1><p className="page__subtitle">Versión {resource.data.version} · configuración cargada al iniciar el backend.</p></div><button className="button" onClick={resource.reload} type="button">Actualizar</button></header>
      {resource.data.rules.map((rule) => (
        <section className="panel" key={rule.id}>
          <div className="page__header"><div><h2 className="panel__title">{rule.title}</h2><p className="page__subtitle"><span className="mono">{rule.id}</span> · {rule.kind} · severidad {rule.severity}</p></div></div>
          <p>{rule.description || "Sin descripción."}</p>
          <h3>Condiciones configuradas</h3>
          <pre className="code code--inline">{JSON.stringify(rule.parameters, null, 2)}</pre>
          {rule.attack.length > 0 ? <>
            <h3>Mapeo MITRE ATT&amp;CK</h3>
            <ul className="evidence-list">{rule.attack.map((mapping) => <li key={mapping.technique_id}>
              <strong>{mapping.technique_name} ({mapping.technique_id})</strong> · {mapping.tactic_name} ({mapping.tactic_id})
              <p>{mapping.rationale}</p>
              <a className="link" href={`https://attack.mitre.org/techniques/${mapping.technique_id.replace(".", "/")}${mapping.technique_id.includes(".") ? "/" : "/"}`} target="_blank" rel="noreferrer">Documentación oficial ATT&amp;CK</a>
            </li>)}</ul>
          </> : <p className="page__subtitle">Esta regla no tiene un mapeo ATT&amp;CK asignado: no hay una asociación suficientemente justificada.</p>}
        </section>
      ))}
    </div>
  );
}
