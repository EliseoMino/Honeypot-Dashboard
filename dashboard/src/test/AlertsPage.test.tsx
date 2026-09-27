import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { AlertsPage } from "../pages/AlertsPage";
import { makeAlertPage, mockBackend, paths } from "./fixtures";

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location">{`${location.pathname}${location.search}`}</span>;
}

function renderAlerts(initialEntry = "/alerts") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <LocationProbe />
      <AlertsPage />
    </MemoryRouter>,
  );
}

function respondAlerts(url: URL) {
  if (url.pathname === "/api/v1/alerts") return { body: makeAlertPage() };
  return undefined;
}

function manyAlerts(url: URL) {
  return {
    body: makeAlertPage({
      total: 90,
      limit: Number(url.searchParams.get("limit") ?? 25),
      offset: Number(url.searchParams.get("offset") ?? 0),
    }),
  };
}

async function lastAlertRequest(calls: { url: string }[]): Promise<URL> {
  await waitFor(() => expect(paths(calls).some((url) => url.includes("/api/v1/alerts?"))).toBe(true));
  const alerts = paths(calls).filter((url) => url.includes("/api/v1/alerts?"));
  return new URL(alerts[alerts.length - 1] as string, "http://dashboard.test");
}

describe("RF-13 consulta de alertas", () => {
  it("visualiza las alertas y el total de resultados", async () => {
    mockBackend(respondAlerts);

    renderAlerts();

    expect(await screen.findByText("Multiple authentication attempts from one IP")).toBeDefined();
    expect(screen.getByText("File download or transfer")).toBeDefined();
    expect(screen.getByText(/1–2 de 2/)).toBeDefined();
  });

  it("muestra la severidad de cada alerta", async () => {
    mockBackend(respondAlerts);

    renderAlerts();

    // Scoped to the table: the severity filter offers the same words as options.
    const table = await screen.findByRole("table");
    expect(within(table).getByText("high")).toBeDefined();
    expect(within(table).getByText("medium")).toBeDefined();
  });

  it("pide la primera página con el límite por defecto", async () => {
    const calls = mockBackend(respondAlerts);

    renderAlerts();

    const url = await lastAlertRequest(calls);
    expect(url.pathname).toBe("/api/v1/alerts");
    expect(url.searchParams.get("limit")).toBe("25");
    expect(url.searchParams.get("offset")).toBe("0");
  });

  it("filtra por severidad y tipo de alerta", async () => {
    const calls = mockBackend(respondAlerts);

    renderAlerts();
    fireEvent.change(await screen.findByLabelText("Severidad"), { target: { value: "critical" } });
    fireEvent.change(screen.getByLabelText("Tipo de alerta"), {
      target: { value: "file_transfer" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Aplicar" }));

    await waitFor(() =>
      expect(screen.getByTestId("location").textContent).toContain("severity=critical"),
    );
    const url = await lastAlertRequest(calls);
    expect(url.searchParams.get("severity")).toBe("critical");
    expect(url.searchParams.get("alert_type")).toBe("file_transfer");
  });

  it("filtra por regla e IP de origen", async () => {
    const calls = mockBackend(respondAlerts);

    renderAlerts();
    fireEvent.change(await screen.findByLabelText("Regla"), {
      target: { value: "auth_bruteforce" },
    });
    fireEvent.change(screen.getByLabelText("IP de origen"), {
      target: { value: "203.0.113.10" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Aplicar" }));

    await waitFor(() =>
      expect(screen.getByTestId("location").textContent).toContain("rule_id=auth_bruteforce"),
    );
    const url = await lastAlertRequest(calls);
    expect(url.searchParams.get("rule_id")).toBe("auth_bruteforce");
    expect(url.searchParams.get("source_ip")).toBe("203.0.113.10");
  });

  it("acepta los filtros que llegan en la URL y ofrece quitarlos", async () => {
    const calls = mockBackend(respondAlerts);

    renderAlerts("/alerts?source_ip=198.51.100.4");

    const url = await lastAlertRequest(calls);
    expect(url.searchParams.get("source_ip")).toBe("198.51.100.4");

    fireEvent.click(screen.getByRole("button", { name: "Limpiar" }));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/alerts"));
  });

  it("limpia todos los filtros", async () => {
    mockBackend(respondAlerts);

    renderAlerts("/alerts?severity=high&rule_id=auth_bruteforce");

    fireEvent.click(await screen.findByRole("button", { name: "Limpiar" }));

    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/alerts"));
  });

  it("vuelve a la primera página al cambiar los filtros", async () => {
    mockBackend(manyAlerts);

    renderAlerts("/alerts?limit=25");
    fireEvent.click(await screen.findByRole("button", { name: "Siguiente" }));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toContain("offset=25"));

    fireEvent.change(screen.getByLabelText("Severidad"), { target: { value: "low" } });
    fireEvent.click(screen.getByRole("button", { name: "Aplicar" }));

    await waitFor(() =>
      expect(screen.getByTestId("location").textContent).not.toContain("offset"),
    );
  });

  it("navega entre páginas", async () => {
    const calls = mockBackend(manyAlerts);

    renderAlerts("/alerts?limit=25");
    fireEvent.click(await screen.findByRole("button", { name: "Siguiente" }));

    await waitFor(() => expect(screen.getByTestId("location").textContent).toContain("offset=25"));
    const url = await lastAlertRequest(calls);
    expect(url.searchParams.get("offset")).toBe("25");
  });

  it("enlaza cada alerta con su detalle", async () => {
    mockBackend(respondAlerts);

    renderAlerts();

    const table = await screen.findByRole("table");
    // The title cell links to the detail, and the last cell repeats it as a
    // button, so both are expected and both have to carry the same href.
    const links = within(table).getAllByRole("link", { name: /Multiple authentication attempts/ });
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      expect(link.getAttribute("href")).toBe("/alerts/1");
    }
  });

  it("explica que no hay alertas hasta que se evaluen las reglas", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/alerts" ? { body: makeAlertPage({ total: 0, items: [] }) } : undefined,
    );

    renderAlerts();

    expect(await screen.findByText(/Todavía no hay alertas/)).toBeDefined();
  });

  it("avisa cuando ningún resultado coincide con los filtros", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/alerts" ? { body: makeAlertPage({ total: 0, items: [] }) } : undefined,
    );

    renderAlerts("/alerts?severity=low");

    expect(await screen.findByText(/Ninguna alerta coincide/)).toBeDefined();
  });

  it("muestra el error del backend", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/alerts"
        ? { status: 422, body: { detail: "'nope' is not a severity level" } }
        : undefined,
    );

    renderAlerts("/alerts?severity=nope");

    expect(await screen.findByText("'nope' is not a severity level")).toBeDefined();
  });
});
