import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { AlertDetailPage } from "../pages/AlertDetailPage";
import { makeAlert, mockBackend } from "./fixtures";

function renderAlert(path = "/alerts/1") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("RF-13 detalle de una alerta", () => {
  it("muestra la alerta y su evidencia", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/alerts/1" ? { body: makeAlert() } : undefined,
    );

    renderAlert();

    expect(await screen.findByText("Multiple authentication attempts from one IP")).toBeDefined();
    expect(screen.getByText(/17 failed logins/)).toBeDefined();
    expect(screen.getAllByText("auth_bruteforce").length).toBeGreaterThan(0);
    expect(screen.getByText("threshold")).toBeDefined();
  });

  it("enlaza cada evento de la evidencia con su detalle", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/alerts/1" ? { body: makeAlert() } : undefined,
    );

    renderAlert();

    const first = await screen.findByRole("link", { name: "e-1" });
    expect(first.getAttribute("href")).toBe("/events/e-1");
    expect(screen.getByRole("link", { name: "e-2" }).getAttribute("href")).toBe("/events/e-2");
  });

  it("enlaza la IP de origen con los eventos filtrados", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/alerts/1" ? { body: makeAlert() } : undefined,
    );

    renderAlert();

    const link = await screen.findByRole("link", { name: "203.0.113.10" });
    expect(link.getAttribute("href")).toBe("/events?source_ip=203.0.113.10");
  });

  it("avisa cuando la detección no guardó los identificadores de los eventos", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/alerts/1"
        ? { body: makeAlert({ evidence: { threshold: 5 } }) }
        : undefined,
    );

    renderAlert();

    expect(
      await screen.findByText(/no guardó los identificadores de los eventos/),
    ).toBeDefined();
  });

  it("muestra el error cuando la alerta no existe", async () => {
    mockBackend((url) =>
      url.pathname === "/api/v1/alerts/9"
        ? { status: 404, body: { detail: "alert 9 was not found" } }
        : undefined,
    );

    renderAlert("/alerts/9");

    expect(await screen.findByText("alert 9 was not found")).toBeDefined();
  });
});
