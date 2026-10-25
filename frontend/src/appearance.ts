export type Appearance = "light" | "dark";
export const APPEARANCE_KEY = "mfa-rotate-appearance";

export function resolveAppearance(value: unknown): Appearance {
  return value === "dark" ? "dark" : "light";
}

export function readAppearance(): Appearance {
  try {
    return resolveAppearance(localStorage.getItem(APPEARANCE_KEY));
  } catch {
    return "light";
  }
}

export function applyAppearance(appearance: Appearance) {
  document.documentElement.dataset.appearance = appearance;
  document.documentElement.classList.toggle("dark", appearance === "dark");
  document.documentElement.style.colorScheme = appearance === "dark" ? "dark" : "light";
  try {
    // This preference contains no account or credential data.
    localStorage.setItem(APPEARANCE_KEY, appearance);
  } catch {
    // Storage restrictions must not prevent switching the current page.
  }
}
