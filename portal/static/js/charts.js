// Draws the health charts with uPlot (vendored by `npm run build:js`):
// sparklines in [data-spark] cells on the dashboard, and the [data-chart]
// panels on a shoveler page from the #series JSON (health.series).
(function () {
  "use strict";
  if (!window.uPlot) return;

  // Tailwind palette, so the charts match the badges and tracker.
  var C = {
    indigo: "#4f46e5", indigoFill: "rgba(79, 70, 229, 0.10)",
    green: "#16a34a", red: "#dc2626", amber: "#d97706",
    slate: "#475569", slateFill: "rgba(71, 85, 105, 0.10)",
    grid: "#e2e8f0", text: "#64748b",
  };
  var FONT = '11px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';

  function fromZero(u, min, max) {
    return [0, max > 0 ? max * 1.1 : 1];
  }

  function compact(v) {
    if (v == null) return "—";
    var a = Math.abs(v);
    if (a >= 1e6) return +(v / 1e6).toFixed(1) + "M";
    if (a >= 1e3) return +(v / 1e3).toFixed(1) + "k";
    return a >= 10 || v === 0 ? Math.round(v).toLocaleString() : +v.toFixed(2) + "";
  }

  function sparkline(el) {
    var ys = JSON.parse(el.dataset.spark);
    var xs = ys.map(function (_, i) { return i; });
    new uPlot({
      width: el.clientWidth, height: el.clientHeight,
      pxAlign: false,
      cursor: { show: false }, select: { show: false }, legend: { show: false },
      scales: { x: { time: false }, y: { range: fromZero } },
      axes: [{ show: false }, { show: false }],
      series: [{}, { stroke: C.indigo, fill: C.indigoFill, width: 1.25 }],
    }, [xs, ys], el);
  }

  var CHARTS = {
    throughput: [
      { key: "received", label: "Received", stroke: C.indigo, fill: C.indigoFill },
      { key: "published", label: "Published", stroke: C.green },
    ],
    queue: [
      { key: "queue", label: "Queued messages", stroke: C.slate, fill: C.slateFill },
    ],
    errors: [
      { key: "failed", label: "Failed validation", stroke: C.red },
      { key: "reconnects", label: "Bus reconnects", stroke: C.amber },
    ],
  };

  function chart(el, data) {
    var defs = CHARTS[el.dataset.chart];
    var axis = { stroke: C.text, font: FONT, grid: { stroke: C.grid, width: 1 },
                 ticks: { stroke: C.grid, width: 1 } };
    var u = new uPlot({
      width: el.clientWidth, height: el.clientHeight,
      // The page shows times in UTC; so do the charts.
      tzDate: function (ts) { return uPlot.tzDate(new Date(ts * 1e3), "Etc/UTC"); },
      cursor: { drag: { x: false, y: false } },
      scales: { y: { range: fromZero } },
      axes: [axis, Object.assign({}, axis, {
        size: 48, values: function (u, vals) { return vals.map(compact); },
      })],
      series: [{ label: "UTC", value: "{YYYY}-{MM}-{DD} {HH}:{mm}" }].concat(
        defs.map(function (d) {
          return { label: d.label, stroke: d.stroke, fill: d.fill, width: 1.5,
                   value: function (u, v) { return compact(v); } };
        })
      ),
    }, [data.t].concat(defs.map(function (d) { return data[d.key]; })), el);
    // The legend sits below the plot; keep the whole chart in its box.
    var legend = el.querySelector(".u-legend");
    var fit = function () {
      u.setSize({ width: el.clientWidth,
                  height: el.clientHeight - (legend ? legend.offsetHeight : 0) });
    };
    fit();
    new ResizeObserver(fit).observe(el);
  }

  document.querySelectorAll("[data-spark]").forEach(sparkline);
  var series = document.getElementById("series");
  if (series) {
    var data = JSON.parse(series.textContent);
    document.querySelectorAll("[data-chart]").forEach(function (el) { chart(el, data); });
  }
})();
