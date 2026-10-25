import { describe, expect, it } from "vitest";
import { AdmissionError, JobAdmission } from "./job-admission";

describe("browser admission queue", () => {
  it("polls once at a time and sends no account operation until a lease arrives", async () => {
    let calls = 0, active = 0, maximum = 0;
    const performed: string[] = [];
    const broker = new JobAdmission(async () => {
      maximum = Math.max(maximum, ++active);
      await Promise.resolve(); active--;
      return ++calls < 3 ? { status: "queued", position: 2, retry_after_ms: 1500 } : { status: "ready", token: `slot-${calls}` };
    }, async () => {}, async () => { expect(performed).toEqual([]); });
    await Promise.all([0, 1].map(index => broker.submit(async token => { performed.push(`${index}:${token}`); }, () => false, () => {})));
    expect(maximum).toBe(1);
    expect(performed).toEqual(["0:slot-3", "1:slot-4"]);
  });

  it("waits for acceptance before requesting the next per-session lease", async () => {
    let requested = 0;
    let release!: () => void;
    const broker = new JobAdmission(async () => ({ status: "ready", token: `slot-${++requested}` }), async () => {});
    const first = broker.submit(async () => new Promise<void>(resolve => { release = resolve; }), () => false, () => {});
    const second = broker.submit(async () => "accepted", () => false, () => {});
    await Promise.resolve(); await Promise.resolve();
    expect(requested).toBe(1);
    release();
    expect(await second).toBe("accepted");
    await first;
    expect(requested).toBe(2);
  });

  it("releases a lease when cancelled before credential submission", async () => {
    let cancelled = false, performed = false;
    const released: string[] = [];
    const broker = new JobAdmission(async () => { cancelled = true; return { status: "ready", token: "held" }; }, async token => { released.push(token); });
    await expect(broker.submit(async () => { performed = true; }, () => cancelled, () => {})).rejects.toMatchObject({ code: "cancelled_before_submit" });
    expect(performed).toBe(false);
    expect(released).toEqual(["held"]);
  });

  it("expires browser waiting without submitting credentials", async () => {
    let requested = false;
    const broker = new JobAdmission(async () => { requested = true; return { status: "ready", token: "unused" }; }, async () => {}, async () => {}, 0);
    await expect(broker.submit(async () => {}, () => false, () => {})).rejects.toBeInstanceOf(AdmissionError);
    expect(requested).toBe(false);
  });
});
