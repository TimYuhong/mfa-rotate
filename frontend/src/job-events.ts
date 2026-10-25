type Watcher = {
  cursor: number;
  failures: number;
  onEvent: (event: any) => Promise<void>;
  resolve: () => void;
  reject: (error: Error) => void;
};
type PollResult = { jobs: Record<string, { events?: any[]; error?: string; done?: boolean }> };

/** One short poll for all jobs, leaving HTTP/1 connections free for ACK/cancel. */
export class JobEvents {
  private watchers = new Map<string, Watcher>();
  private running = false;
  constructor(private poll: (cursors: Record<string, number>) => Promise<PollResult>, private interval = 400) {}

  watch(id: string, onEvent: Watcher["onEvent"]): Promise<void> {
    if (this.watchers.has(id)) return Promise.reject(new Error("该任务正在核对中"));
    const promise = new Promise<void>((resolve, reject) => this.watchers.set(id, { cursor: 0, failures: 0, onEvent, resolve, reject }));
    if (!this.running) void this.run();
    return promise;
  }

  private fail(id: string, watcher: Watcher, error: Error) {
    this.watchers.delete(id);
    watcher.reject(error);
  }

  private async run() {
    this.running = true;
    try {
      while (this.watchers.size) {
        const batch = [...this.watchers.entries()].slice(0, 50);
        try {
          const response = await this.poll(Object.fromEntries(batch.map(([id, watcher]) => [id, watcher.cursor])));
          await Promise.all(batch.map(async ([id, watcher]) => {
            try {
              const job = response.jobs[id];
              if (!job || job.error) {
                this.fail(id, watcher, new Error("任务已过期或不可访问，请保留密钥并核对账户"));
                return;
              }
              for (const event of job.events ?? []) {
                if (event.seq <= watcher.cursor) continue;
                await watcher.onEvent(event);
                watcher.cursor = event.seq;
                if (event.type === "done") {
                  this.watchers.delete(id);
                  watcher.resolve();
                  break;
                }
              }
              watcher.failures = 0;
            } catch (error) {
              if (++watcher.failures >= 5) this.fail(id, watcher, error as Error);
            }
          }));
        } catch (error) {
          for (const [id, watcher] of batch) {
            if (++watcher.failures >= 5) this.fail(id, watcher, error as Error);
          }
        }
        if (this.watchers.size) await new Promise(resolve => setTimeout(resolve, this.interval));
      }
    } finally {
      this.running = false;
    }
  }
}
