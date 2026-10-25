// Adapted from rdev/liquid-glass-react, commit ac48eab18d1f7f444ae30002d240cae29c863a21.
// Copyright 2025 MAX ROVENSKY. MIT; see GLASS-SOURCE.json and assets/licenses/liquid-glass-react.txt.
import { useEffect, useId, useRef } from "react";

const displacementMap = "/assets/liquid-glass-prominent.png";
const displacementScale = 52;
const aberrationIntensity = 0.85;

/** Background material only: Radix owns layout, focus, keyboard and confirmation. */
export function DialogGlass() {
  const id = `dialog-lens-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const definitions = useRef<SVGSVGElement>(null);

  useEffect(() => {
    const panel = definitions.current?.closest<HTMLElement>(".glass-dialog");
    if (!panel) return;
    panel.dataset.glassSource = "rdev/liquid-glass-react";
    const supported = !/Firefox|Version\/.*Safari/.test(navigator.userAgent)
      && CSS.supports("backdrop-filter", "blur(1px)") && CSS.supports("filter", `url(#${id})`);
    let active = true;
    const image = new Image();
    const measure = () => {
      // Layout dimensions stay stable while Radix animates its transform.
      const width = panel.offsetWidth, height = panel.offsetHeight;
      if (!width || !height) return;
      panel.style.setProperty("--glass-width", `${width}px`);
      panel.style.setProperty("--glass-height", `${height}px`);
    };
    if (supported) {
      image.onload = () => {
        if (!active) return;
        panel.style.setProperty("--glass-lens", `url("#${id}")`);
        panel.dataset.glassMode = "lens";
      };
      image.src = displacementMap;
    }
    measure();
    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(measure);
    observer?.observe(panel);
    window.addEventListener("resize", measure);
    return () => {
      active = false;
      image.onload = null;
      observer?.disconnect();
      window.removeEventListener("resize", measure);
      for (const name of ["--glass-lens", "--glass-width", "--glass-height"]) panel.style.removeProperty(name);
      delete panel.dataset.glassSource;
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
      // Upstream's pointer-directed edge highlight, without moving business controls.
      panel.style.setProperty("--glass-light-angle", `${135 + (x - 50) * 0.45}deg`);
    };
    const reset = () => {
      cancelAnimationFrame(frame); frame = 0;
      x = 25; y = 0; paint();
      panel.dataset.glassPaused = String(document.hidden || motion.matches);
    };
    const move = (event: PointerEvent) => {
      if (motion.matches || document.hidden || event.pointerType !== "mouse") return;
      const box = panel.getBoundingClientRect();
      if (!box.width || !box.height) return;
      x = Math.max(0, Math.min(100, (event.clientX - box.left) / box.width * 100));
      y = Math.max(0, Math.min(100, (event.clientY - box.top) / box.height * 100));
      if (!frame) frame = requestAnimationFrame(paint);
    };
    panel.addEventListener("pointermove", move);
    panel.addEventListener("pointerleave", reset);
    motion.addEventListener("change", reset);
    document.addEventListener("visibilitychange", reset);
    reset();
    return () => {
      cancelAnimationFrame(frame);
      panel.removeEventListener("pointermove", move);
      panel.removeEventListener("pointerleave", reset);
      motion.removeEventListener("change", reset);
      document.removeEventListener("visibilitychange", reset);
      delete panel.dataset.glassPaused;
      for (const name of ["--glass-light-x", "--glass-light-y", "--glass-light-angle"]) panel.style.removeProperty(name);
    };
  }, []);

  return <>
    <svg ref={definitions} className="glass-filter-defs" style={{ width: "var(--glass-width, 0px)", height: "var(--glass-height, 0px)" }} aria-hidden="true" focusable="false">
      <defs>
        {/* Upstream GlassFilter: preserve the clean center and refract the edge in RGB. */}
        <filter id={id} x="-35%" y="-35%" width="170%" height="170%" colorInterpolationFilters="sRGB">
          <feImage href={displacementMap} x="0" y="0" width="100%" height="100%" result="DISPLACEMENT_MAP" preserveAspectRatio="none" />
          <feColorMatrix in="DISPLACEMENT_MAP" type="matrix" values="0.3 0.3 0.3 0 0  0.3 0.3 0.3 0 0  0.3 0.3 0.3 0 0  0 0 0 1 0" result="EDGE_INTENSITY" />
          <feComponentTransfer in="EDGE_INTENSITY" result="EDGE_MASK">
            <feFuncA type="discrete" tableValues={`0 ${aberrationIntensity * 0.05} 1`} />
          </feComponentTransfer>
          <feOffset in="SourceGraphic" dx="0" dy="0" result="CENTER_ORIGINAL" />
          <feDisplacementMap in="SourceGraphic" in2="DISPLACEMENT_MAP" scale={-displacementScale} xChannelSelector="R" yChannelSelector="B" result="RED_DISPLACED" />
          <feColorMatrix in="RED_DISPLACED" type="matrix" values="1 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 1 0" result="RED_CHANNEL" />
          <feDisplacementMap in="SourceGraphic" in2="DISPLACEMENT_MAP" scale={displacementScale * (-1 - aberrationIntensity * 0.05)} xChannelSelector="R" yChannelSelector="B" result="GREEN_DISPLACED" />
          <feColorMatrix in="GREEN_DISPLACED" type="matrix" values="0 0 0 0 0  0 1 0 0 0  0 0 0 0 0  0 0 0 1 0" result="GREEN_CHANNEL" />
          <feDisplacementMap in="SourceGraphic" in2="DISPLACEMENT_MAP" scale={displacementScale * (-1 - aberrationIntensity * 0.1)} xChannelSelector="R" yChannelSelector="B" result="BLUE_DISPLACED" />
          <feColorMatrix in="BLUE_DISPLACED" type="matrix" values="0 0 0 0 0  0 0 0 0 0  0 0 1 0 0  0 0 0 1 0" result="BLUE_CHANNEL" />
          <feBlend in="GREEN_CHANNEL" in2="BLUE_CHANNEL" mode="screen" result="GB_COMBINED" />
          <feBlend in="RED_CHANNEL" in2="GB_COMBINED" mode="screen" result="RGB_COMBINED" />
          <feGaussianBlur in="RGB_COMBINED" stdDeviation={Math.max(0.1, 0.5 - aberrationIntensity * 0.1)} result="ABERRATED_BLURRED" />
          <feComposite in="ABERRATED_BLURRED" in2="EDGE_MASK" operator="in" result="EDGE_ABERRATION" />
          <feComponentTransfer in="EDGE_MASK" result="INVERTED_MASK"><feFuncA type="table" tableValues="1 0" /></feComponentTransfer>
          <feComposite in="CENTER_ORIGINAL" in2="INVERTED_MASK" operator="in" result="CENTER_CLEAN" />
          <feComposite in="EDGE_ABERRATION" in2="CENTER_CLEAN" operator="over" />
        </filter>
      </defs>
    </svg>
    <span className="glass-warp" aria-hidden="true" />
    <span className="glass-tint" aria-hidden="true" />
    <span className="glass-rim-flow" aria-hidden="true" />
  </>;
}
