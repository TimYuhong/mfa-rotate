// Adapted from Magic UI ShineBorder, efe76fc5755eca1142dd4f74c1d6f0ace2887e3c.
// Copyright (c) Magic UI. MIT; see VISUAL-SOURCES.json and assets/licenses/magic-ui.txt.
import { useEffect, useRef, useState, type CSSProperties } from "react";

/** A decorative border for the running-task toolbar; it never estimates progress. */
export function ProcessingAccent() {
  const node = useRef<HTMLDivElement>(null);
  const [paused, setPaused] = useState(document.hidden);
  useEffect(() => {
    let visible = true;
    const update = () => setPaused(document.hidden || !visible);
    const observer = new IntersectionObserver(entries => { visible = entries.some(entry => entry.isIntersecting); update(); });
    if (node.current) observer.observe(node.current);
    document.addEventListener("visibilitychange", update);
    return () => { observer.disconnect(); document.removeEventListener("visibilitychange", update); };
  }, []);
  return <div ref={node} className="processing-accent" data-paused={paused} aria-hidden="true" style={{
    backgroundImage: "radial-gradient(transparent, transparent, hsl(var(--detail) / 0.55), transparent, transparent)",
    backgroundSize: "300% 300%",
    mask: "linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)",
    WebkitMask: "linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)",
    WebkitMaskComposite: "xor", maskComposite: "exclude", padding: "1px",
  } as CSSProperties} />;
}
