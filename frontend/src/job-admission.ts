type Slot = { status: "ready"; token: string } | { status: "queued"; position: number; retry_after_ms: number };
type Submission = {
  perform: (token: string) => Promise<unknown>;
  cancelled: () => boolean;
  waiting: () => void;
  deadline: number;
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
};

export class AdmissionError extends Error {
  constructor(public code: "cancelled_before_submit" | "queue_timeout" | "admission_failed", message?: string) {
    super(message ?? (code === "queue_timeout" ? "等待超时，本任务未提交" : "未开始，已取消"));
  }
}

/** One polling stream per page. Only submission is serialized; accepted jobs run concurrently. */
export class JobAdmission {
  private pending: Submission[] = [];
  private draining = false;

  constructor(
    private request: () => Promise<Slot>,
    private release: (token: string) => Promise<unknown>,
    private pause: (milliseconds: number) => Promise<void> = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)),
    private maximumWaitMs = 600_000,
  ) {}

  submit<T>(perform: (token: string) => Promise<T>, cancelled: () => boolean, waiting: () => void): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.pending.push({ perform, cancelled, waiting, deadline: Date.now() + this.maximumWaitMs, resolve: value => resolve(value as T), reject });
      if (!this.draining) void this.drain();
    });
  }

  private async drain() {
    this.draining = true;
    try {
      while (this.pending.length) {
        const task = this.pending[0];
        let token = "", submitted = false;
        try {
          while (!token) {
            for (let index = this.pending.length - 1; index > 0; index--) {
              const pending = this.pending[index];
              if (pending.cancelled() || Date.now() >= pending.deadline) {
                this.pending.splice(index, 1);
                pending.reject(new AdmissionError(pending.cancelled() ? "cancelled_before_submit" : "queue_timeout"));
              }
            }
            if (task.cancelled()) throw new AdmissionError("cancelled_before_submit");
            if (Date.now() >= task.deadline) throw new AdmissionError("queue_timeout");
            const slot = await this.request();
            if (slot.status === "ready") token = slot.token;
            else {
              task.waiting();
              await this.pause(Math.max(1000, Math.min(3000, slot.retry_after_ms)));
            }
          }
          if (task.cancelled()) throw new AdmissionError("cancelled_before_submit");
          // Wait for acceptance before requesting another lease, avoiding duplicate
          // use of the same per-session token by this page's parallel task runners.
          submitted = true;
          task.resolve(await task.perform(token));
        } catch (error) {
          if (token) await this.release(token).catch(() => {});
          task.reject(!submitted && !(error instanceof AdmissionError)
            ? new AdmissionError("admission_failed", error instanceof Error ? error.message : "排队请求未完成，本任务未提交") : error);
        } finally {
          this.pending.shift();
        }
      }
    } finally {
      this.draining = false;
    }
  }
}
