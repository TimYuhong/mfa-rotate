import { JobEvents } from "./job-events";

let csrf = "";
export const setCsrf = (value: string) => {
  csrf = value;
};
export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
  }
}
export async function api(path: string, method = "GET", body?: unknown, timeoutMs = 15000) {
  const response = await fetch("/api" + path, {
    method,
    credentials: "same-origin",
    cache: "no-store",
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      ...(method !== "GET"
        ? { "Content-Type": "application/json", "X-CSRF-Token": csrf }
        : {}),
    },
    ...(method !== "GET" ? { body: JSON.stringify(body ?? {}) } : {}),
  });
  const data = await response.json();
  if (!response.ok && data.code === "session_expired") window.dispatchEvent(new Event("mfa-session-expired"));
  if (!response.ok)
    throw new ApiError(
      data.code ?? "request_failed",
      data.message ?? "请求失败",
    );
  return data;
}
const events = new JobEvents(cursors => api("/job-events", "POST", { cursors }));
export const consume = (id: string, onEvent: (event: any) => Promise<void>) => events.watch(id, onEvent);
