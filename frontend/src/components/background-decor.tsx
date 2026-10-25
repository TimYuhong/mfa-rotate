import { useEffect, useState, type CSSProperties } from "react";
import { Snowflake } from "lucide-react";
import { Label } from "./ui";
import { Switch } from "./ui/switch";

const snowKey = "mfa-rotate-light-snow";
// Stable variation avoids restarting the trajectories when visibility or theme changes.
function snowVariation(index: number, seed: number) {
  const value = Math.sin((index + 1) * (12.9898 + seed * 78.233)) * 43758.5453;
  return value - Math.floor(value);
}
const snowFlakes = Array.from({ length: 36 }, (_, i) => {
  const duration = 16 + snowVariation(i, 1) * 18;
  return {
    crystal: i % 3 === 0,
    style: {
      "--flake-x": `${3 + ((i * 13 % 36) + snowVariation(i, 2)) / 36 * 94}%`,
      "--flake-size": `${i % 3 === 0 ? 12 + Math.floor(snowVariation(i, 3) * 3) * 2 : 4 + Math.floor(snowVariation(i, 3) * 3)}px`,
      "--flake-depth": 0.7 + snowVariation(i, 4) * 0.3,
      "--flake-duration": `${duration}s`,
      "--flake-delay": `${-duration * (0.1 + 0.8 * ((i * 17 % 36) + snowVariation(i, 5)) / 36)}s`,
      "--flake-delay-mobile": `${-duration * (0.1 + 0.8 * ((i * 7 % 16) + snowVariation(i, 5)) / 16)}s`,
      "--flake-drift": `${(snowVariation(i, 6) - 0.5) * 60}px`,
      "--flake-sway": `${14 + snowVariation(i, 7) * 34}px`,
      "--flake-sway-mobile": `${7 + snowVariation(i, 7) * 15}px`,
      "--flake-sway-duration": `${3.5 + snowVariation(i, 8) * 5.5}s`,
      "--flake-sway-delay": `${-snowVariation(i, 9) * 16}s`,
      "--flake-sway-direction": i % 2 ? "alternate-reverse" : "alternate",
      "--flake-angle-start": `${-55 + snowVariation(i, 10) * 50}deg`,
      "--flake-angle-end": `${45 + snowVariation(i, 11) * 100}deg`,
    } as CSSProperties,
  };
});
export function useLightSnow() {
  const [snow, setSnow] = useState(() => { try { return localStorage.getItem(snowKey) === "true"; } catch { return false; } });
  return [snow, (value: boolean) => { setSnow(value); try { localStorage.setItem(snowKey, String(value)); } catch { /* Appearance only. */ } }] as const;
}
export function SnowControl({ value, onChange }: { value: boolean; onChange: (value: boolean) => void }) {
  return <Label className="snow-control" title="轻雪仅在本浏览器显示">
    <Snowflake size={15} /><span>轻雪</span><span className="switch-target"><Switch checked={value} onCheckedChange={onChange} aria-label="轻雪" /></span>
  </Label>;
}
export function BackgroundDecor({ snow }: { snow: boolean }) {
  const [visible, setVisible] = useState(!document.hidden);
  const [reduced, setReduced] = useState(() => matchMedia("(prefers-reduced-motion: reduce)").matches);
  useEffect(() => {
    const preference = matchMedia("(prefers-reduced-motion: reduce)");
    const onVisibility = () => setVisible(!document.hidden), onMotion = () => setReduced(preference.matches);
    document.addEventListener("visibilitychange", onVisibility);
    preference.addEventListener("change", onMotion);
    return () => { document.removeEventListener("visibilitychange", onVisibility); preference.removeEventListener("change", onMotion); };
  }, []);
  return snow && !reduced ? <div className="snow-layer" data-paused={!visible} aria-hidden="true">
      {snowFlakes.map((flake, i) => <span className="snow-flake" data-shape={flake.crystal ? "crystal" : "dot"} key={i} style={flake.style}>
        <span className="snow-particle">{flake.crystal && <Snowflake strokeWidth={1.4} />}</span>
      </span>)}
    </div> : null;
}
