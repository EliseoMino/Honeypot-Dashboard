import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { EventDetailPage } from "../pages/EventDetailPage";
import { makeEvent, mockBackend, paths } from "./fixtures";

function renderDetail(eventId: string) {
  return render(
    <MemoryRouter initialEntries={[`/events/${eventId}`]}>
      <Routes>
        <Route path="/events/:eventId" element={<EventDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("RF-07 detalle de un evento", () => {
  it("consulta el evento indicado", async () => {
    const calls = mockBackend(() => ({ body: makeEvent() }));

    renderDetail("e-1");

    expect(await screen.findByRole("heading", { name: "auth.login_failed" })).toBeDefined();
    expect(paths(calls)).toContain("/api/v1/events/e-1");
  });

  it("muestra los atributos comunes y la información específica", async () => {
    mockBackend(() => ({ body: makeEvent() }));

    renderDetail("e-1");

    expect(await screen.findByText("203.0.113.10")).toBeDefined();
    expect(screen.getByText("sess-1")).toBeDefined();
    expect(screen.getByText("10.0.0.5:22")).toBeDefined();
    expect(screen.getByText("Atributos comunes")).toBeDefined();
    expect(screen.getByText("Información específica")).toBeDefined();
    expect(screen.getByText("123456")).toBeDefined();
  });

  it("enlaza el evento con su sesión y su IP de origen", async () => {
    mockBackend(() => ({ body: makeEvent() }));

    renderDetail("e-1");

    const session = await screen.findByRole("link", { name: "sess-1" });
    const ip = screen.getByRole("link", { name: "203.0.113.10" });

    expect(session.getAttribute("href")).toBe("/events?session_id=sess-1");
    expect(ip.getAttribute("href")).toBe("/events?source_ip=203.0.113.10");
  });

  it("oculta el log original hasta que se pide", async () => {
    mockBackend(() => ({ body: makeEvent() }));

    renderDetail("e-1");

    const toggle = await screen.findByRole("button", { name: "Mostrar" });
    expect(screen.queryByText(/"eventid": "cowrie.login.failed"/)).toBeNull();

    fireEvent.click(toggle);
    expect(screen.getByText(/"eventid": "cowrie.login.failed"/)).toBeDefined();
  });

  it("relaciona el log original con el evento normalizado en la misma vista", async () => {
    // RF-14 asks for the original log to be relatable to the normalized event.
    // Both live in one record, and the key that ties them is the Cowrie
    // eventid, shown next to the raw payload.
    mockBackend(() => ({ body: makeEvent() }));

    renderDetail("e-1");

    fireEvent.click(await screen.findByRole("button", { name: "Mostrar" }));

    // The normalized side: the fields Cowrie does not know about.
    expect(screen.getByText("e-1")).toBeDefined();
    expect(screen.getByText("honeypot-1")).toBeDefined();
    expect(screen.getByText("51234")).toBeDefined();

    // The key both sides share.
    expect(screen.getByText("cowrie.login.failed")).toBeDefined();

    // The original side: the payload exactly as Cowrie emitted it.
    expect(screen.getByText(/"eventid": "cowrie.login.failed"/)).toBeDefined();
    expect(screen.getByText(/"username": "root"/)).toBeDefined();
  });

  it("informa cuando el evento no existe", async () => {
    mockBackend(() => ({ status: 404, body: { detail: "event 'nope' not found" } }));

    renderDetail("nope");

    expect(await screen.findByText("event 'nope' not found")).toBeDefined();
  });

  it("avisa cuando el evento no tiene atributos específicos", async () => {
    mockBackend(() => ({ body: makeEvent({ details: {} }) }));

    renderDetail("e-1");

    expect(await screen.findByText("Este evento no tiene atributos específicos.")).toBeDefined();
  });
});
