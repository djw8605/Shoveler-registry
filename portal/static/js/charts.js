// Draws a shoveler page's charts with uPlot (vendored by `npm run build:js`)
// from the #series JSON (health.series), one per [data-chart] element.
// Times are UTC, like the rest of the page; the charts share one cursor, and
// dragging across one zooms it (double-click resets).
(function () {
  "use strict";
  var source = document.getElementById("series");
  if (!window.uPlot || !source) return;
  var data = JSON.parse(source.textContent);

  // Tailwind palette. Red and amber mean a health status elsewhere on the
  // page, so only bus reconnects borrow amber; nothing here is red.
  var C = {
    indigo: "#4f46e5",
    green: "#16a34a", greenFill: "rgba(22, 163, 74, 0.14)",
    slate: "#475569", slateFill: "rgba(71, 85, 105, 0.12)",
    muted: "#64748b", amber: "#d97706",
    grid: "#e2e8f0", text: "#64748b",
  };
  var FONT = '11px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';

  var CHARTS = {
    // Published is the filled area and received the line over it, so the
    // two separate visibly when the shoveler stops publishing.
    throughput: { floor: 1, series: [
      { key: "published", label: "Published", stroke: C.green, fill: C.greenFill },
      { key: "received", label: "Received", stroke: C.indigo },
    ] },
    // Up to 100 queued messages sit in memory as a matter of course.
    queue: { floor: 100, series: [
      { key: "queue", label: "Queued messages", stroke: C.slate, fill: C.slateFill },
    ] },
    errors: { floor: 1, series: [
      { key: "failed", label: "Failed validation", stroke: C.muted },
      { key: "reconnects", label: "Bus reconnects", stroke: C.amber },
    ] },
  };

  var utc = function (ts) { return uPlot.tzDate(new Date(ts * 1e3), "Etc/UTC"); };
  var hhmm = uPlot.fmtDate("{HH}:{mm}");
  var day = uPlot.fmtDate("{YYYY}-{MM}-{DD}");
  var stamp = uPlot.fmtDate("{YYYY}-{MM}-{DD} {HH}:{mm} UTC");

  function compact(v) {
    var a = Math.abs(v);
    if (a >= 1e6) return +(v / 1e6).toFixed(1) + "M";
    if (a >= 1e3) return +(v / 1e3).toFixed(1) + "k";
    return a >= 10 || v === 0 ? String(Math.round(v)) : String(+v.toFixed(2));
  }

  // The legend names the series; values appear only while hovering.
  function hovered(fmt) {
    return function (u, v, s, idx) { return idx == null || v == null ? "" : fmt(v); };
  }

  function chart(el) {
    var def = CHARTS[el.dataset.chart];
    var axis = { stroke: C.text, font: FONT, grid: { stroke: C.grid, width: 1 },
                 ticks: { stroke: C.grid, width: 1 } };
    var u = new uPlot({
      width: el.clientWidth, height: el.clientHeight,
      tzDate: utc,
      cursor: { sync: { key: "shoveler" }, drag: { x: true, y: false } },
      scales: { y: { range: function (u, min, max) {
        // From zero, and small values don't fill the whole height.
        return [0, Math.max(max * 1.1, def.floor)];
      } } },
      axes: [
        Object.assign({}, axis, { values: function (u, splits) {
          return splits.map(function (ts) {
            var d = utc(ts);
            return d.getHours() === 0 && d.getMinutes() === 0 ? day(d) : hhmm(d);
          });
        } }),
        Object.assign({}, axis, { size: 48, values: function (u, vals) {
          return vals.map(compact);
        } }),
      ],
      series: [{ value: hovered(function (ts) { return stamp(utc(ts)); }) }]
        .concat(def.series.map(function (d) {
          return { label: d.label, stroke: d.stroke, fill: d.fill, width: 1.5,
                   value: hovered(compact) };
        })),
    }, [data.t].concat(def.series.map(function (d) { return data[d.key]; })), el);
    // Keep plot + legend inside the element's fixed height.
    var legend = el.querySelector(".u-legend");
    var fit = function () {
      u.setSize({ width: el.clientWidth,
                  height: el.clientHeight - (legend ? legend.offsetHeight : 0) });
    };
    fit();
    new ResizeObserver(fit).observe(el);
  }

  document.querySelectorAll("[data-chart]").forEach(chart);
})();
