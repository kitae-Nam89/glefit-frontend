import React, { useEffect, useRef } from "react";

export default function OverlayHighlighter({ container, ranges, color = "rgba(255,0,0,0.18)" }) {
  const ref = useRef(null);

  useEffect(() => {
    const el = ref.current;
    const root = container;
    if (!el || !root) return;
    el.innerHTML = "";
    const base = root.getBoundingClientRect();

    ranges.forEach((rg) => {
      const rects = rg.getClientRects();
      Array.from(rects).forEach((r) => {
        const box = document.createElement("div");
        box.style.position = "absolute";
        box.style.left = `${r.left - base.left + root.scrollLeft}px`;
        box.style.top = `${r.top - base.top + root.scrollTop}px`;
        box.style.width = `${r.width}px`;
        box.style.height = `${r.height}px`;
        box.style.background = color;
        box.style.borderRadius = "4px";
        el.appendChild(box);
      });
    });
  }, [container, ranges, color]);

  return <div ref={ref} style={{ position: "absolute", inset: 0, pointerEvents: "none" }} />;
}