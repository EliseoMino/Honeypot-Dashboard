import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { SummaryPage } from "../pages/SummaryPage";
import { TimeSeriesChart } from "../components/TimeSeriesChart";
import { makeSummary, makeTimeSeries, mockBackend, paths } from "./fixtures";

function renderChart(points = makeTimeSeries().points, bucket: "hour" | "day" = "hour") {
  return render(<TimeSeriesChart points={points} bucket={bucket} title="Evolución de la actividad" />);
}

/** Points whose data attribute carries the period they represent. */
function periodLabels(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll(".chart__hit")).map(
    (node) => node.getAttribute("aria-label") ?? "",
  );
}

describe("RF-05 visualización temporal de la actividad", () => {
  it("dibuja el gráfico con un punto por periodo con eventos", () => {
    const { container } = renderChart();

    const chart = container.querySelector("svg") as SVGElement;
    expect(chart).toBeDefined();
    expect(chart.getAttribute("role")).toBe("img");
    expect(container.querySelectorAll(".chart__hit")).toHaveLength(3);
  });

  it("rellena los periodos sin actividad con cero, para que un silencio se vea", () => {
    // The API only returns the periods that have events: 10:00 and 13:00.
    const { container } = renderChart([
      { bucket: "2026-03-01T10:00:00+00:00", count: 4, auth: 4, commands: 0 },
      { bucket: "2026-03-01T13:00:00+00:00", count: 1, auth: 0, commands: 1 },
    ]);

    // Without the gaps the axis would collapse 10:00 to 13:00 into two points
    // and the lull in between would be invisible, which is what RF-05 asks to see.
    expect(container.querySelectorAll(".chart__hit")).toHaveLength(4);
    const labels = periodLabels(container);
    expect(labels[2]).toMatch(/0 eventos/);
  });

  it("distingue autenticaciones de comandos en la leyenda y en el texto", () => {
    renderChart();

    expect(screen.getByText("Autenticaciones")).toBeDefined();
    expect(screen.getByText("Comandos")).toBeDefined();
    expect(screen.getByText("Total")).toBeDefined();
  });

  it("lee un periodo concreto al pasar el cursor por él", () => {
    const { container } = renderChart();

    const target = container.querySelectorAll(".chart__hit")[1] as SVGElement;
    fireEvent.mouseEnter(target);

    const readout = screen.getByTestId("chart-readout");
    expect(readout.textContent).toContain("7 eventos");
    expect(readout.textContent).toContain("1 autenticaciones");
    expect(readout.textContent).toContain("6 comandos");
  });

  it("expone cada periodo con una etiqueta legible para lectores de pantalla", () => {
    const { container } = renderChart();

    const labels = periodLabels(container);
    expect(labels).toHaveLength(3);
    expect(labels[0]).toContain("2 eventos");
    expect(labels[1]).toContain("7 eventos");
  });

  it("avisa cuando el periodo seleccionado no tiene actividad", () => {
    renderChart([], "day");

    expect(screen.getByText(/No hay actividad en el periodo seleccionado/)).toBeDefined();
  });

  it("el resumen pide la serie con el periodo elegido y lo cambia bajo demanda", async () => {
    const calls = mockBackend((url) => {
      if (url.pathname === "/api/v1/events/summary") return { body: makeSummary() };
      if (url.pathname === "/api/v1/events/timeseries") {
        return { body: makeTimeSeries({ bucket: (url.searchParams.get("bucket") ?? "hour") as "hour" | "day" }) };
      }
      return undefined;
    });

    render(
      <MemoryRouter initialEntries={["/"]}>
        <SummaryPage />
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(paths(calls).some((url) => url.includes("/api/v1/events/timeseries?bucket=hour"))).toBe(true),
    );

    fireEvent.change(screen.getByLabelText("Periodo del gráfico"), { target: { value: "day" } });

    await waitFor(() =>
      expect(paths(calls).some((url) => url.includes("/api/v1/events/timeseries?bucket=day"))).toBe(true),
    );
  });

  it("el resumen informa cuando la serie no se puede consultar", async () => {
    mockBackend((url) => {
      if (url.pathname === "/api/v1/events/summary") return { body: makeSummary() };
      if (url.pathname === "/api/v1/events/timeseries") {
        return { status: 500, body: { detail: "boom" } };
      }
      return undefined;
    });

    render(
      <MemoryRouter initialEntries={["/"]}>
        <SummaryPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/boom/)).toBeDefined();
  });
});
