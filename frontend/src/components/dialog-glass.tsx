// SVG-only adaptation of React Bits GlassSurface, commit e12c22192ac7b4b452c5e2feb9b586d74765d696.
// Copyright (c) 2026 David Haz. MIT + Commons Clause; see GLASS-SOURCE.json and public/assets/licenses/react-bits.txt.
import { useEffect, useId, useRef } from "react";

/** Visual material only. Radix retains focus, keyboard, dismissal and confirmation semantics. */
export function DialogGlass() {
  const id = `dialog-lens-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const definitions = useRef<SVGSVGElement>(null);
  const map = useRef<SVGFEImageElement>(null);

  useEffect(() => {
    const panel = definitions.current?.closest<HTMLElement>(".glass-dialog");
    if (!panel) return;
    const supported = !/Firefox|Version\/.*Safari/.test(navigator.userAgent) && CSS.supports("backdrop-filter", `url(#${id})`);
    if (!supported) return;
    panel.style.setProperty("--glass-lens", `url("#${id}")`);
    panel.dataset.glassMode = "lens";
    let lastSize = "";
    const update = () => {
      const width = panel.offsetWidth, height = panel.offsetHeight;
      const signature = `${width}x${height}`;
      if (!width || !height || signature === lastSize) return;
      lastSize = signature;
      const radius = 28, edge = Math.min(width, height) * 0.065;
      // Upstream's neutral-center RG displacement map bends the perimeter, not the content.
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
        <defs>
          <linearGradient id="x" x1="100%" x2="0%"><stop stop-color="#0000"/><stop offset="1" stop-color="red"/></linearGradient>
          <linearGradient id="y" x2="0%" y2="100%"><stop stop-color="#0000"/><stop offset="1" stop-color="blue"/></linearGradient>
          <filter id="soft"><feGaussianBlur stdDeviation="6"/></filter>
        </defs>
        <rect width="100%" height="100%" fill="black"/>
        <rect width="100%" height="100%" rx="${radius}" fill="url(#x)"/>
        <rect width="100%" height="100%" rx="${radius}" fill="url(#y)" style="mix-blend-mode:difference"/>
        <rect x="${edge}" y="${edge}" width="${width - edge * 2}" height="${height - edge * 2}" rx="${radius}" fill="#808080" filter="url(#soft)"/>
      </svg>`;
      map.current?.setAttribute("href", `data:image/svg+xml,${encodeURIComponent(svg)}`);
    };
    update();
    const observer = new ResizeObserver(update);
    observer.observe(panel);
    return () => {
      observer.disconnect();
      panel.style.removeProperty("--glass-lens");
      delete panel.dataset.glassMode;
    };
  }, [id]);

  useEffect(() => {
    const panel = definitions.current?.closest<HTMLElement>(".glass-dialog");
    if (!panel) return;
    const motion = matchMedia("(prefers-reduced-motion: reduce)");
    let frame = 0, x = 25, y = 0;
    const paint = () => {
      frame = 0;
      panel.style.setProperty("--glass-light-x", `${x}%`);
      panel.style.setProperty("--glass-light-y", `${y}%`);
    };
    const reset = () => {
      cancelAnimationFrame(frame); frame = 0;
      x = 25; y = 0; paint();
    };
    const move = (event: PointerEvent) => {
      if (motion.matches || event.pointerType !== "mouse") return;
      const box = panel.getBoundingClientRect();
      x = Math.max(0, Math.min(100, (event.clientX - box.left) / box.width * 100));
      y = Math.max(0, Math.min(100, (event.clientY - box.top) / box.height * 100));
      if (!frame) frame = requestAnimationFrame(paint);
    };
    panel.addEventListener("pointermove", move);
    panel.addEventListener("pointerleave", reset);
    motion.addEventListener("change", reset);
    return () => {
      cancelAnimationFrame(frame);
      panel.removeEventListener("pointermove", move);
      panel.removeEventListener("pointerleave", reset);
      motion.removeEventListener("change", reset);
      panel.style.removeProperty("--glass-light-x");
      panel.style.removeProperty("--glass-light-y");
    };
  }, []);

  return <svg ref={definitions} className="glass-filter-defs" width="0" height="0" aria-hidden="true" focusable="false">
    <defs>
      <filter id={id} colorInterpolationFilters="sRGB" x="0%" y="0%" width="100%" height="100%">
        <feImage ref={map} width="100%" height="100%" preserveAspectRatio="none" result="map" />
        <feDisplacementMap in="SourceGraphic" in2="map" scale="-70" xChannelSelector="R" yChannelSelector="G" result="red-shift" />
        <feColorMatrix in="red-shift" type="matrix" values="1 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 1 0" result="red" />
        <feDisplacementMap in="SourceGraphic" in2="map" scale="-69" xChannelSelector="R" yChannelSelector="G" result="green-shift" />
        <feColorMatrix in="green-shift" type="matrix" values="0 0 0 0 0  0 1 0 0 0  0 0 0 0 0  0 0 0 1 0" result="green" />
        <feDisplacementMap in="SourceGraphic" in2="map" scale="-68" xChannelSelector="R" yChannelSelector="G" result="blue-shift" />
        <feColorMatrix in="blue-shift" type="matrix" values="0 0 0 0 0  0 0 0 0 0  0 0 1 0 0  0 0 0 1 0" result="blue" />
        <feBlend in="red" in2="green" mode="screen" result="rg" />
        <feBlend in="rg" in2="blue" mode="screen" />
        <feGaussianBlur stdDeviation="0.6" />
      </filter>
    </defs>
  </svg>;
}
