import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { EventsPage } from "../pages/EventsPage";
import { makePage, makeSummary, mockBackend, paths } from "./fixtures";

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location">{`${location.pathname}${location.search}`}</span>;
}

function renderEvents(initialEntry = "/events") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <LocationProbe />
      <EventsPage />
    </MemoryRouter>,
  );
}

/** The event types suggestion list uses the summary endpoint. */
function respondEvents(url: URL) {
  if (url.pathname === "/api/v1/events/summary") return { body: makeSummary() };
  if (url.pathname === "/api/v1/events") return { body: makePage() };
  return undefined;
}

/** A result set with enough rows to page through. */
function manyEvents(url: URL) {
  if (url.pathname === "/api/v1/events/summary") return { body: makeSummary() };
  return {
    body: makePage({
      total: 120,
      limit: Number(url.searchParams.get("limit") ?? 25),
      offset: Number(url.searchParams.get("offset") ?? 0),
    }),
  };
}

async function lastEventRequest(calls: { url: string }[]): Promise<URL> {
  await waitFor(() => expect(paths(calls).some((url) => url.includes("/api/v1/events?"))).toBe(true));
  const events = paths(calls).filter((url) => url.includes("/api/v1/events?"));
  return new URL(events[events.length - 1] as string, "http://dashboard.test");
}

describe("RF-06 consulta de eventos", () => {
  it("visualiza los eventos y el total de resultados", async () => {
    mockBackend(respondEvents);

    renderEvents();

    expect(await screen.findByText("auth.login_failed")).toBeDefined();
    expect(screen.getByText("command.success")).toBeDefined();
    expect(screen.getByText(/1–2 de 2/)).toBeDefined();
  });

  it("pide los eventos ordenados por fecha descendente por defecto", async () => {
    const calls = mockBackend(respondEvents);

    renderEvents();

    const url = await lastEventRequest(calls);
    expect(url.searchParams.get("order")).toBe("desc");
    expect(url.searchParams.get("limit")).toBe("50");
    expect(url.searchParams.get("offset")).toBe("0");
  });

  it("ordena de forma ascendente al pulsar la cabecera de fecha", async () => {
    const calls = mockBackend(respondEvents);

    renderEvents();
    fireEvent.click(await screen.findByRole("button", { name: /Fecha/ }));

    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/events?order=asc"));
    const url = await lastEventRequest(calls);
    expect(url.searchParams.get("order")).toBe("asc");
  });

  it("combina los filtros de texto, tipo e IP de origen", async () => {
    const calls = mockBackend(respondEvents);

    renderEvents();
    fireEvent.change(await screen.findByLabelText("Buscar texto"), {
      target: { value: "wget" },
    });
    fireEvent.change(screen.getByLabelText("Tipo de evento"), {
      target: { value: "auth.login_failed" },
    });
    fireEvent.change(screen.getByLabelText("IP de origen"), {
      target: { value: "203.0.113.10" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Aplicar" }));

    await waitFor(() =>
      expect(screen.getByTestId("location").textContent).toContain("event_type=auth.login_failed"),
    );
    const url = await lastEventRequest(calls);
    expect(url.searchParams.get("q")).toBe("wget");
    expect(url.searchParams.get("event_type")).toBe("auth.login_failed");
    expect(url.searchParams.get("source_ip")).toBe("203.0.113.10");
  });

  it("vuelve a la primera página al cambiar los filtros", async () => {
    mockBackend(manyEvents);

    renderEvents("/events?limit=25");
    fireEvent.click(await screen.findByRole("button", { name: "Siguiente" }));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toContain("offset=25"));

    fireEvent.change(screen.getByLabelText("Buscar texto"), { target: { value: "root" } });
    fireEvent.click(screen.getByRole("button", { name: "Aplicar" }));

    await waitFor(() =>
      expect(screen.getByTestId("location").textContent).not.toContain("offset"),
    );
  });

  it("navega entre páginas", async () => {
    const calls = mockBackend(manyEvents);

    renderEvents("/events?limit=25");
    fireEvent.click(await screen.findByRole("button", { name: "Siguiente" }));

    await waitFor(() => expect(screen.getByTestId("location").textContent).toContain("offset=25"));
    const url = await lastEventRequest(calls);
    expect(url.searchParams.get("offset")).toBe("25");
  });

  it("acepta los filtros que llegan en la URL y ofrece quitarlos", async () => {
    const calls = mockBackend(respondEvents);

    renderEvents("/events?session_id=sess-1");

    expect(await screen.findByText("sess-1")).toBeDefined();
    const url = await lastEventRequest(calls);
    expect(url.searchParams.get("session_id")).toBe("sess-1");

    fireEvent.click(screen.getByRole("button", { name: "Quitar" }));
    await waitFor(() =>
      expect(screen.getByTestId("location").textContent).not.toContain("session_id"),
    );
  });

  it("limpia todos los filtros", async () => {
    mockBackend(respondEvents);

    renderEvents("/events?event_type=command.success&source_ip=203.0.113.10");

    fireEvent.click(await screen.findByRole("button", { name: "Limpiar" }));

    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/events"));
  });

  it("avisa cuando ningún evento coincide con los filtros", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/events/summary"
        ? { body: makeSummary() }
        : { body: makePage({ total: 0, items: [] }) },
    );

    renderEvents("/events?q=nada");

    expect(await screen.findByText(/Ningún evento coincide/)).toBeDefined();
  });

  it("muestra el error del backend", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/events/summary"
        ? { body: makeSummary() }
        : { status: 422, body: { detail: "'nope' is not a valid IP address" } },
    );

    renderEvents("/events?source_ip=nope");

    expect(await screen.findByText("'nope' is not a valid IP address")).toBeDefined();
  });
});
