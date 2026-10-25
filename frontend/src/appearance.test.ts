import { afterEach, describe, expect, it, vi } from "vitest";
import { APPEARANCE_KEY, applyAppearance, readAppearance, resolveAppearance } from "./appearance";

afterEach(() => vi.unstubAllGlobals());

describe("page appearance", () => {
  it("accepts the two supported appearances only", () => {
    for (const value of ["light", "dark"] as const) {
      expect(resolveAppearance(value)).toBe(value);
    }
    for (const value of [null, undefined, "compact", "system", "__proto__", {}, "DARK"]) {
      expect(resolveAppearance(value)).toBe("light");
    }
  });

  it("reads only the appearance preference", () => {
    const getItem = vi.fn(() => "dark");
    vi.stubGlobal("localStorage", { getItem });
    expect(readAppearance()).toBe("dark");
    expect(getItem).toHaveBeenCalledWith(APPEARANCE_KEY);
  });

  it("falls back to light for the removed compact preference", () => {
    vi.stubGlobal("localStorage", { getItem: () => "compact" });
    expect(readAppearance()).toBe("light");
  });

  it("works when browser storage is blocked", () => {
    const toggle = vi.fn();
    const root = { dataset: {}, classList: { toggle }, style: {} };
    vi.stubGlobal("document", { documentElement: root });
    vi.stubGlobal("localStorage", {
      getItem() { throw new Error("blocked"); },
      setItem() { throw new Error("blocked"); },
    });
    expect(readAppearance()).toBe("light");
    expect(() => applyAppearance("dark")).not.toThrow();
    expect(root.dataset).toEqual({ appearance: "dark" });
    expect(root.style).toEqual({ colorScheme: "dark" });
    expect(toggle).toHaveBeenCalledWith("dark", true);
  });

  it("persists appearance and resets dark mode when switching back", () => {
    const toggle = vi.fn();
    const setItem = vi.fn();
    vi.stubGlobal("document", { documentElement: { dataset: {}, classList: { toggle }, style: {} } });
    vi.stubGlobal("localStorage", { setItem });
    applyAppearance("dark");
    applyAppearance("light");
    expect(toggle).toHaveBeenLastCalledWith("dark", false);
    expect(setItem).toHaveBeenLastCalledWith(APPEARANCE_KEY, "light");
  });
});
