import type { ReactNode } from "react";
import { NavLink, Route, Routes } from "react-router-dom";

import { EmptyState } from "./components/Feedback";
import { EventDetailPage } from "./pages/EventDetailPage";
import { EventsPage } from "./pages/EventsPage";
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
          <NavLink className="app__link" to="/events">
            Eventos
          </NavLink>
        </nav>
      </header>

      <main className="app__main">
        <Routes>
          <Route path="/" element={<SummaryPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/events/:eventId" element={<EventDetailPage />} />
          <Route
            path="*"
            element={<EmptyState>La página solicitada no existe.</EmptyState>}
          />
        </Routes>
      </main>
    </div>
  );
}
