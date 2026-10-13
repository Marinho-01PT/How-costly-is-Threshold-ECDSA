// Small line icons as inline SVG (24 x 24, drawn with currentColor).

const NS = "http://www.w3.org/2000/svg";

const PATHS = {
  key: "M14.5 9.5a4.5 4.5 0 1 1-9 0 4.5 4.5 0 0 1 9 0Z M13.2 12.7 21 20.5 M17.5 17l2-2 M15 14.5l2-2",
  split: "M12 3v18 M8 6H5a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3 M16 6h3a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-3",
  pen: "M4 20l4-1 11-11-3-3L5 16l-1 4Z M14 7l3 3",
  check: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z M8 12.5l2.7 2.7L16 9.8",
  swap: "M4 8h13l-3-3 M20 16H7l3 3",
  people: "M8 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z M16 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z M2.5 19c.6-3 2.8-5 5.5-5s4.9 2 5.5 5 M10.5 19c.6-3 2.8-5 5.5-5s4.9 2 5.5 5",
  warning: "M12 3 2 20h20L12 3Z M12 10v4.5 M12 17.2v.3",
  lock: "M6 11h12v10H6z M8.5 11V8a3.5 3.5 0 0 1 7 0v3",
  unlock: "M6 11h12v10H6z M8.5 11V8a3.5 3.5 0 0 1 6.8-1.2",
  arrow: "M4 12h15 M14 7l5 5-5 5",
};

export function icon(name, cls = "icon") {
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", cls);
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", PATHS[name]);
  svg.append(path);
  return svg;
}

// One icon per section of the trace.
export const SECTION_ICONS = {
  keygen: "key", sharing: "split", sign: "pen", verify: "check",
  mta: "swap", twoparty: "people", reuse: "warning",
};
