import type { ReactNode } from "react";
import { NavLink, Route, Routes } from "react-router-dom";

import { EmptyState } from "./components/Feedback";
import { AlertDetailPage } from "./pages/AlertDetailPage";
import { AlertsPage } from "./pages/AlertsPage";
import { CommandsPage } from "./pages/CommandsPage";
import { EventDetailPage } from "./pages/EventDetailPage";
import { EventsPage } from "./pages/EventsPage";
import { SessionsPage } from "./pages/SessionsPage";
import { SourceDetailPage } from "./pages/SourceDetailPage";
import { SourcesPage } from "./pages/SourcesPage";
import { SummaryPage } from "./pages/SummaryPage";

export function App(): ReactNode {
  return (
    <div className="app">
      <header className="app__bar">
        <span className="app__brand">Honeypot Dashboard</span>
        <nav className="app__nav">
          <NavLink className="app__link" to="/" end>
            Resumen
          </NavLink>
          <NavLink className="app__link" to="/alerts">
            Alertas
          </NavLink>
          <NavLink className="app__link" to="/events">
            Eventos
          </NavLink>
          <NavLink className="app__link" to="/sessions">
            Sesiones
          </NavLink>
          <NavLink className="app__link" to="/commands">
            Comandos
          </NavLink>
          <NavLink className="app__link" to="/sources">
            IPs
          </NavLink>
        </nav>
      </header>

      <main className="app__main">
        <Routes>
          <Route path="/" element={<SummaryPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/events/:eventId" element={<EventDetailPage />} />
          <Route path="/sessions" element={<SessionsPage />} />
          <Route path="/commands" element={<CommandsPage />} />
          <Route path="/sources" element={<SourcesPage />} />
          <Route path="/sources/:sourceIp" element={<SourceDetailPage />} />
          <Route
            path="*"
            element={<EmptyState>La página solicitada no existe.</EmptyState>}
          />
        </Routes>
      </main>
    </div>
  );
}
