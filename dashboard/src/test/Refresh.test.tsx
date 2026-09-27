/**
 * RF-15 — the data of the dashboard refreshes by itself.
 *
 * The tests use fake timers, because the requirement is about a period of time
 * passing, and a recording `fetch` stub, so the assertions are about the
 * requests the dashboard makes and not about the layout.
 */

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useAutoRefresh } from "../hooks/useAutoRefresh";
import { REFRESH_INTERVALS, REFRESH_STORAGE_KEY } from "../hooks/useRefreshPreference";
import { EventsPage } from "../pages/EventsPage";
import { SummaryPage } from "../pages/SummaryPage";
import {
  makePage,
  makeSummary,
  makeTimeSeries,
  mockBackend,
  paths,
  type RecordedRequest,
} from "./fixtures";

const FASTEST = REFRESH_INTERVALS[0].value;

function renderSummary() {
  return render(
    <MemoryRouter>
      <SummaryPage />
    </MemoryRouter>,
  );
}

function respond(url: URL) {
  if (url.pathname === "/api/v1/events/summary") return { body: makeSummary() };
  if (url.pathname === "/api/v1/events/timeseries") return { body: makeTimeSeries() };
  if (url.pathname === "/api/v1/events") return { body: makePage() };
  return undefined;
}

function summaryCalls(calls: RecordedRequest[]): number {
  return paths(calls).filter((url) => url.includes("/api/v1/events/summary")).length;
}

function eventCalls(calls: RecordedRequest[]): number {
  return paths(calls).filter((url) => url.includes("/api/v1/events?")).length;
}

/** Store a preference before the page reads it on mount. */
function storePreference(preference: { enabled: boolean; intervalMs: number }): void {
  window.localStorage.setItem(REFRESH_STORAGE_KEY, JSON.stringify(preference));
}

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  window.localStorage.clear();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("RF-15 actualización automática", () => {
  it("recarga el resumen cada intervalo", async () => {
    storePreference({ enabled: true, intervalMs: FASTEST });
    const calls = mockBackend(respond);

    renderSummary();
    await waitFor(() => expect(summaryCalls(calls)).toBe(1));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(FASTEST);
    });
    expect(summaryCalls(calls)).toBe(2);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(FASTEST);
    });
    expect(summaryCalls(calls)).toBe(3);
  });

  it("recarga la lista de eventos conservando los filtros", async () => {
    storePreference({ enabled: true, intervalMs: FASTEST });
    const calls = mockBackend(respond);

    render(
      <MemoryRouter initialEntries={["/events?source_ip=203.0.113.10"]}>
        <EventsPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(eventCalls(calls)).toBe(1));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(FASTEST);
    });

    const requests = paths(calls).filter((url) => url.includes("/api/v1/events?"));
    expect(requests).toHaveLength(2);
    expect(requests[1]).toContain("source_ip=203.0.113.10");
  });

  it("no recarga nada cuando la actualización automática está desactivada", async () => {
    storePreference({ enabled: false, intervalMs: FASTEST });
    const calls = mockBackend(respond);

    renderSummary();
    await waitFor(() => expect(summaryCalls(calls)).toBe(1));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(FASTEST * 5);
    });

    expect(summaryCalls(calls)).toBe(1);
  });

  it("empieza a recargar en cuanto se activa", async () => {
    storePreference({ enabled: false, intervalMs: FASTEST });
    const calls = mockBackend(respond);

    renderSummary();
    await waitFor(() => expect(summaryCalls(calls)).toBe(1));

    // Awaited, not queried straight away: counting the request only proves it
    // was sent, not that the controls are on screen yet.
    fireEvent.click(await screen.findByLabelText("Actualización automática"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(FASTEST);
    });

    expect(summaryCalls(calls)).toBe(2);
  });

  it("deja de recargar en cuanto se desactiva", async () => {
    storePreference({ enabled: true, intervalMs: FASTEST });
    const calls = mockBackend(respond);

    renderSummary();
    await waitFor(() => expect(summaryCalls(calls)).toBe(1));

    fireEvent.click(await screen.findByLabelText("Actualización automática"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(FASTEST * 3);
    });

    expect(summaryCalls(calls)).toBe(1);
  });

  it("no duplica una petición que sigue en curso", async () => {
    storePreference({ enabled: true, intervalMs: FASTEST });

    // The request is never answered, so the dashboard stays busy and the ticks
    // that pass must not turn into more requests.
    let started = 0;
    vi.stubGlobal(
      "fetch",
      () =>
        new Promise<Response>(() => {
          started += 1;
        }),
    );

    renderSummary();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(FASTEST * 3);
    });

    // One per resource on the page: RF-05 added the activity series next to the
    // counters, and neither of them may be asked for twice.
    expect(started).toBe(2);
  });

  it("recarga una vez al volver a la pestaña", async () => {
    storePreference({ enabled: true, intervalMs: FASTEST });
    const calls = mockBackend(respond);

    renderSummary();
    await waitFor(() => expect(summaryCalls(calls)).toBe(1));

    // jsdom reports the document as visible, so the event is a return to the tab.
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
    });

    await waitFor(() => expect(summaryCalls(calls)).toBe(2));
  });

  it("deja de recargar al desmontar la vista", async () => {
    storePreference({ enabled: true, intervalMs: FASTEST });
    const calls = mockBackend(respond);

    const view = renderSummary();
    await waitFor(() => expect(summaryCalls(calls)).toBe(1));

    view.unmount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(FASTEST * 3);
    });

    expect(summaryCalls(calls)).toBe(1);
  });
});

describe("RF-15 actualización manual", () => {
  it("el botón recarga bajo demanda", async () => {
    storePreference({ enabled: false, intervalMs: FASTEST });
    const calls = mockBackend(respond);

    renderSummary();
    await waitFor(() => expect(screen.getByText("Eventos totales")).toBeDefined());

    fireEvent.click(screen.getByRole("button", { name: "Actualizar" }));

    await waitFor(() => expect(summaryCalls(calls)).toBe(2));
  });

  it("indica cuándo se cargaron los datos", async () => {
    storePreference({ enabled: false, intervalMs: FASTEST });
    mockBackend(respond);

    renderSummary();

    expect(await screen.findByText(/Última actualización:/)).toBeDefined();
  });

  it("el selector de intervalo queda desactivado sin actualización automática", async () => {
    storePreference({ enabled: false, intervalMs: FASTEST });
    mockBackend(respond);

    renderSummary();

    // Named, because RF-05 added a second select to this page for the chart
    // period, so "the only combobox" is no longer a thing.
    expect(
      await screen.findByLabelText("Intervalo de actualización automática"),
    ).toHaveProperty("disabled", true);
  });
});

describe("RF-15 preferencia recordada", () => {
  it("recuerda la preferencia entre visitas", async () => {
    storePreference({ enabled: false, intervalMs: REFRESH_INTERVALS[1].value });
    mockBackend(respond);

    renderSummary();

    const checkbox = await screen.findByLabelText("Actualización automática");
    expect((checkbox as HTMLInputElement).checked).toBe(false);
    expect(
      (screen.getByLabelText("Intervalo de actualización automática") as HTMLSelectElement).value,
    ).toBe(String(REFRESH_INTERVALS[1].value));
  });

  it("usa la actualización automática por defecto", async () => {
    const calls = mockBackend(respond);

    renderSummary();

    expect(await screen.findByLabelText("Actualización automática")).toHaveProperty(
      "checked",
      true,
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    expect(summaryCalls(calls)).toBeGreaterThan(1);
  });

  it("ignora un valor guardado que no se puede entender", async () => {
    window.localStorage.setItem(REFRESH_STORAGE_KEY, "not json");
    mockBackend(respond);

    renderSummary();

    expect(await screen.findByLabelText("Actualización automática")).toHaveProperty(
      "checked",
      true,
    );
  });
});

describe("useAutoRefresh", () => {
  it("no programa nada mientras está desactivado", () => {
    const reload = vi.fn();
    const Ticker = (): null => {
      useAutoRefresh({ enabled: false, intervalMs: FASTEST, reload, busy: false });
      return null;
    };

    render(<Ticker />);
    act(() => {
      vi.advanceTimersByTime(FASTEST * 3);
    });

    expect(reload).not.toHaveBeenCalled();
  });
});
