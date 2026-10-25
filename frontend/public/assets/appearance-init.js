// Apply the saved preference before paint, under the existing CSP/static route.
try {
  const saved = localStorage.getItem("mfa-rotate-appearance");
  const appearance = saved === "dark" ? "dark" : "light";
  document.documentElement.dataset.appearance = appearance;
  document.documentElement.classList.toggle("dark", appearance === "dark");
  document.documentElement.style.colorScheme = appearance === "dark" ? "dark" : "light";
} catch {
  document.documentElement.style.colorScheme = "light";
}
