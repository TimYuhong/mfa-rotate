export type Outcome = "running" | "success" | "failed" | "cancelled";
export type RetryAction = "rotate" | "verify" | "check" | "none";
export type TaskFilter = "all" | "running" | "queued" | "success" | "failed" | "cancelled";

export function taskCategory(task: { outcome: Outcome; stage: string }): Exclude<TaskFilter, "all"> {
  return task.outcome === "running" ? (task.stage === "queued" ? "queued" : "running") : task.outcome;
}

export function retryAction(state: string, uncertain = false): RetryAction {
  if (uncertain) return "check";
  if (state === "unchanged") return "rotate";
  if (state === "enabled_unverified" || state === "activation_unknown") return "verify";
  return "none";
}

export function failurePhase(state: string, uncertain = false): string {
  if (uncertain) return "执行状态待核对";
  if (state === "unchanged") return "更换前失败 · 旧密钥未变更";
  if (state === "enabled_unverified") return "更换后验证失败 · 仅重试验证";
  if (state === "activation_unknown") return "启用结果待核对 · 仅验证新密钥";
  return "变更中断 · 请保留密钥并人工核对";
}

