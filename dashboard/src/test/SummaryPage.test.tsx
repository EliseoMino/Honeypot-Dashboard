import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { SummaryPage } from "../pages/SummaryPage";
import { makeSummary, mockBackend, paths } from "./fixtures";

function renderSummary() {
  return render(
    <MemoryRouter>
      <SummaryPage />
    </MemoryRouter>,
  );
}

describe("RF-04 dashboard de resumen", () => {
  it("muestra los seis indicadores pedidos", async () => {
    mockBackend(() => ({ body: makeSummary() }));

    renderSummary();

    expect(await screen.findByText("Eventos totales")).toBeDefined();
    expect(screen.getByText("IPs únicas")).toBeDefined();
    expect(screen.getByText("Sesiones")).toBeDefined();
    expect(screen.getByText("Intentos de autenticación")).toBeDefined();
    expect(screen.getByText("Comandos registrados")).toBeDefined();
    expect(screen.getByText("Alertas generadas")).toBeDefined();

    expect(screen.getByText("120")).toBeDefined();
    expect(screen.getByText("80")).toBeDefined();
    expect(screen.getByText("25")).toBeDefined();
  });

  it("aclara que el contador de alertas es un marcador de posición", async () => {
    mockBackend(() => ({ body: makeSummary() }));

    renderSummary();

    expect(await screen.findByText(/Pendiente de RF-11 y RF-12/)).toBeDefined();
  });

  it("detalla el rango temporal y los tipos más frecuentes", async () => {
    mockBackend(() => ({ body: makeSummary() }));

    renderSummary();

    expect(await screen.findByText(/UTC/)).toBeDefined();
    expect(screen.getByText("Tipos de evento más frecuentes")).toBeDefined();
    expect(screen.getByText("auth.login_failed")).toBeDefined();
  });

  it("avisa cuando no hay eventos almacenados", async () => {
    mockBackend(() => ({
      body: makeSummary({
        total_events: 0,
        unique_source_ips: 0,
        unique_sessions: 0,
        auth_attempts: 0,
        commands: 0,
        first_event_at: null,
        last_event_at: null,
        by_category: [],
        by_outcome: [],
        by_protocol: [],
        top_event_types: [],
      }),
    }));

    renderSummary();

    expect(await screen.findByText(/Todavía no hay eventos almacenados/)).toBeDefined();
  });

  it("muestra el error del backend y permite reintentar", async () => {
    const calls = mockBackend(() => ({
      status: 500,
      body: { detail: "boom" },
    }));

    renderSummary();

    expect(await screen.findByRole("alert")).toBeDefined();
    expect(paths(calls)).toEqual(["/api/v1/events/summary"]);

    fireEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    await waitFor(() => expect(paths(calls).length).toBe(2));
  });
});
