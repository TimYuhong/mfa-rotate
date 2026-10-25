type WaitingTask = { execute: () => Promise<void>; resolve: () => void; reject: (error: unknown) => void };

/** One FIFO queue shared by initial submissions and explicit retries. */
export class TaskQueue {
  private active = 0;
  private waiting: WaitingTask[] = [];
  private limit = 1;

  constructor(limit: number) { this.setLimit(limit); }

  setLimit(limit: number) {
    this.limit = Math.max(1, Math.min(10, Math.floor(limit) || 1));
    this.drain();
  }

  enqueue(execute: () => Promise<void>): Promise<void> {
    return new Promise((resolve, reject) => {
      this.waiting.push({ execute, resolve, reject });
      this.drain();
    });
  }

  private drain() {
    while (this.active < this.limit && this.waiting.length) {
      const task = this.waiting.shift()!;
      this.active++;
      void Promise.resolve().then(task.execute).then(task.resolve, task.reject).finally(() => {
        this.active--;
        this.drain();
      });
    }
  }
}
