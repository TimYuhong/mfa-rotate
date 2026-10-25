import type { Outcome } from "./task-state";

// Milestones describe workflow stages, not elapsed time or network byte progress.
const stages: Record<string, number> = {
  queued: 0,
  authenticating: 10,
  checking: 25,
  reauthenticating: 40,
  removing: 50,
  enrolling: 60,
  awaiting_receipt: 70,
  activating: 85,
  verifying: 95,
};
const states: Record<string, number> = {
  unchanged: 0,
  removal_unknown: 50,
  old_factor_removed: 60,
  enrollment_pending: 70,
  activation_unknown: 85,
  enabled_unverified: 95,
};

export function taskProgress(stage: string, state: string, outcome: Outcome, previous = 0): number {
  if (outcome === "success") return 100;
  // Stopped/unknown events have no new milestone. Preserve the last observation.
  const observed = Number.isFinite(previous) ? previous : 0;
  return Math.min(99, Math.max(0, observed, stages[stage] ?? 0, states[state] ?? 0));
}
