import { Progress } from "./ui/progress";
import type { Outcome } from "../task-state";

const outcomeLabel: Record<Outcome, string> = {
  running: "进行中", success: "已完成", failed: "失败", cancelled: "已取消",
};

export function TaskProgress({ account, value, outcome, status }: { account: string; value: number; outcome: Outcome; status?: string }) {
  return (
    <div className="task-progress" data-outcome={outcome} title={`阶段进度 ${value}%`}>
      <Progress
        className="task-progress-track"
        value={value}
        max={100}
        aria-label={`${account} 的任务进度`}
        aria-valuetext={`${status ?? outcomeLabel[outcome]}，阶段进度 ${value}%`}
      />
      <span className="task-progress-value" aria-hidden="true">{value}%</span>
    </div>
  );
}
