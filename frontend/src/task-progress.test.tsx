import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { taskProgress } from "./task-progress";
import { Progress } from "./components/ui/progress";

describe("task stage progress", () => {
  it("only marks a verified success as complete", () => {
    expect(taskProgress("complete", "verified", "success", 95)).toBe(100);
    expect(taskProgress("verifying", "enabled_unverified", "running")).toBeLessThan(100);
    expect(taskProgress("stopped", "enabled_unverified", "failed")).toBeLessThan(100);
    expect(taskProgress("queued", "unchanged", "running")).toBe(0);
  });

  it("retains the observed milestone on failure, cancellation or event replay", () => {
    const observed = taskProgress("awaiting_receipt", "enrollment_pending", "running");
    expect(taskProgress("stopped", "enrollment_pending", "failed", observed)).toBe(observed);
    expect(taskProgress("stopped", "enrollment_pending", "cancelled", observed)).toBe(observed);
    expect(taskProgress("authenticating", "unchanged", "running", observed)).toBe(observed);
  });

  it("resets a new rotation and keeps verification retries at their confirmed phase", () => {
    expect(taskProgress("queued", "unchanged", "running")).toBe(0);
    expect(taskProgress("queued", "enabled_unverified", "running")).toBeGreaterThan(80);
    expect(taskProgress("unknown", "unknown", "failed", NaN)).toBe(0);
  });

  it("exposes the displayed number as accessible determinate progress", () => {
    for (const value of [0, 50, 100]) {
      const markup = renderToStaticMarkup(<Progress value={value} aria-label="任务进度" />);
      expect(markup).toContain('role="progressbar"');
      expect(markup).toContain(`aria-valuenow="${value}"`);
      expect(markup).toContain(`aria-valuemax="100"`);
      expect(markup).toContain(`translateX(-${100 - value}%)`);
    }
  });
});
