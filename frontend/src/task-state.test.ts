import { describe, expect, it } from "vitest";
import { countTasks, retryAction, taskCategory, type Outcome } from "./task-state";
import { TaskQueue } from "./task-queue";
import { JobEvents } from "./job-events";

describe("task filter counts", () => {
  it("shows every category as zero when there are no tasks", () => {
    expect(countTasks([])).toEqual({ all: 0, running: 0, queued: 0, success: 0, failed: 0, cancelled: 0 });
  });

  it("counts the complete batch and gives terminal outcomes priority over a queued stage", () => {
    const rows: { outcome: Outcome; stage: string }[] = [
      ...Array.from({ length: 15 }, () => ({ outcome: "running" as const, stage: "queued" })),
      ...Array.from({ length: 10 }, () => ({ outcome: "running" as const, stage: "authenticating" })),
      ...Array.from({ length: 8 }, () => ({ outcome: "success" as const, stage: "complete" })),
      ...Array.from({ length: 6 }, () => ({ outcome: "failed" as const, stage: "queued" })),
      ...Array.from({ length: 3 }, () => ({ outcome: "cancelled" as const, stage: "queued" })),
    ];
    expect(countTasks(rows)).toEqual({ all: 42, running: 10, queued: 15, success: 8, failed: 6, cancelled: 3 });
  });

  it("moves a retried task between buckets without adding an attempt to the total", () => {
    const task: { outcome: Outcome; stage: string } = { outcome: "failed", stage: "stopped" };
    const rows = [task];
    expect(countTasks(rows)).toEqual({ all: 1, running: 0, queued: 0, success: 0, failed: 1, cancelled: 0 });
    task.outcome = "running"; task.stage = "queued";
    expect(countTasks(rows)).toEqual({ all: 1, running: 0, queued: 1, success: 0, failed: 0, cancelled: 0 });
    task.stage = "verifying";
    expect(countTasks(rows)).toEqual({ all: 1, running: 1, queued: 0, success: 0, failed: 0, cancelled: 0 });
    task.outcome = "success"; task.stage = "complete";
    expect(countTasks(rows)).toEqual({ all: 1, running: 0, queued: 0, success: 1, failed: 0, cancelled: 0 });
    rows.splice(0, 1);
    expect(countTasks(rows).all).toBe(0);
  });
});

describe("task isolation and retries", () => {
  it("only retries full rotation before a confirmed mutation", () => {
    expect(retryAction("unchanged")).toBe("rotate");
    expect(retryAction("enabled_unverified")).toBe("verify");
    expect(retryAction("activation_unknown")).toBe("verify");
    for (const state of ["removal_unknown", "old_factor_removed", "enrollment_pending", "verified"]) expect(retryAction(state)).toBe("none");
    expect(retryAction("unchanged", true)).toBe("check");
  });
  it("bounds the pool at ten and runs every item", async () => {
    let active = 0, maximum = 0;
    const completed: number[] = [];
    const scheduler = new TaskQueue(100);
    await Promise.all(Array.from({ length: 25 }, (_, item) => scheduler.enqueue(async () => {
      maximum = Math.max(maximum, ++active);
      await new Promise(resolve => setTimeout(resolve, 2));
      completed.push(item); active--;
    })));
    expect(maximum).toBe(10);
    expect(completed).toHaveLength(25);
  });
  it("places retries after existing waiting tasks in the same queue", async () => {
    const scheduler = new TaskQueue(1);
    const order: string[] = [];
    let release!: () => void;
    const started = new Promise<void>(resolve => {
      void scheduler.enqueue(async () => {
        order.push("active"); resolve();
        await new Promise<void>(r => { release = r; });
      });
    });
    await started;
    const waiting = scheduler.enqueue(async () => { order.push("waiting"); });
    const retry = scheduler.enqueue(async () => { order.push("retry"); });
    expect(order).toEqual(["active"]);
    release();
    await Promise.all([waiting, retry]);
    expect(order).toEqual(["active", "waiting", "retry"]);
  });
  it("separates waiting from executing without changing terminal outcomes", () => {
    expect(taskCategory({ outcome: "running", stage: "queued" })).toBe("queued");
    expect(taskCategory({ outcome: "running", stage: "verifying" })).toBe("running");
    expect(taskCategory({ outcome: "cancelled", stage: "queued" })).toBe("cancelled");
    expect(taskCategory({ outcome: "failed", stage: "stopped" })).toBe("failed");
  });
  it("multiplexes ten watches without ten long-lived requests", async () => {
    const batches: number[] = [];
    const hub = new JobEvents(async cursors => {
      batches.push(Object.keys(cursors).length);
      return { jobs: Object.fromEntries(Object.keys(cursors).map(id => [id, { events: [{ seq: 1, type: "done" }] }])) };
    }, 0);
    await Promise.all(Array.from({ length: 10 }, (_, id) => hub.watch(String(id), async () => {})));
    expect(batches).toEqual([1, 9]);
  });
  it("does not advance a failed delivery cursor or block another task", async () => {
    let failOnce = true;
    const cursorsSeen: Record<string, number>[] = [];
    const finished: string[] = [];
    const hub = new JobEvents(async cursors => {
      cursorsSeen.push(cursors);
      return { jobs: Object.fromEntries(Object.keys(cursors).map(id => [id, { events: [{ seq: 1, type: "done" }] }])) };
    }, 0);
    await Promise.all([hub.watch("a", async () => { if (failOnce) { failOnce = false; throw new Error("storage"); } finished.push("a"); }),
      hub.watch("b", async () => { finished.push("b"); })]);
    expect(cursorsSeen[1].a).toBe(0);
    expect(finished.sort()).toEqual(["a", "b"]);
  });
});
