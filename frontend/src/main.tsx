import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  CheckCircle2,
  Download,
  ArrowRight,
  Eye,
  EyeOff,
  FileText,
  LoaderCircle,
  LockKeyhole,
  KeyRound,
  ListChecks,
  Moon,
  Sun,
  RotateCw,
  CircleX,
  Ban,
  Clock3,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import {
  Button,
  Card,
  Checkbox,
  Label,
  Badge,
  Alert,
  AlertTitle,
  AlertDescription,
  Input,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Textarea,
} from "./components/ui";
import { Confirm, ClearResultConfirm } from "./components/confirm-rotation";
import { FeedbackDialog } from "./components/feedback-dialog";
import { ProcessingAccent } from "./components/processing-accent";
import { parseLines, parseSingle, type Credential } from "./parser";
import { credentialText } from "./export";
import { readCredentialFile } from "./import-file";
import { api, ApiError, consume, setCsrf } from "./api";
import { AdmissionError, JobAdmission } from "./job-admission";
import * as vault from "./vault";
import { applyAppearance, readAppearance, type Appearance } from "./appearance";
import { countTasks, failurePhase, retryAction, taskCategory, type Outcome, type TaskFilter } from "./task-state";
import { TaskQueue } from "./task-queue";
import { taskProgress } from "./task-progress";
import { TaskProgress } from "./components/task-progress";
import { CopyButton } from "./components/copy-button";
import { useListPage } from "./list-page";
import { ListPagination } from "./components/list-pagination";
import { ProxyPoolCard } from "./components/proxy-pool";
import { useProxyPool, type NetworkRoute } from "./use-proxy-pool";
import { BackgroundDecor, SnowControl, useLightSnow } from "./components/background-decor";
import "./style.css";

const admission = new JobAdmission(
  () => api("/job-slots", "POST", {}),
  token => api(`/job-slots/${token}`, "DELETE"),
);

const stageName: Record<string, string> = {
  queued: "队列中",
  authenticating: "验证账号",
  checking: "检查验证器",
  reauthenticating: "确认身份",
  removing: "移除旧因子",
  enrolling: "生成新密钥",
  awaiting_receipt: "本机保存新密钥",
  activating: "激活新密钥",
  verifying: "独立登录验证",
  complete: "已完成",
  stopped: "已停止",
};
const stateName: Record<string, string> = {
  verified: "已验证",
  unchanged: "未变更",
  removal_unknown: "移除结果未知",
  old_factor_removed: "旧因子已移除",
  enrollment_pending: "尚未激活",
  activation_unknown: "激活结果未知",
  enabled_unverified: "已启用 · 待验证",
};
type Row = {
  id: string;
  email: string;
  stage: string;
  state: string;
  message?: string;
  job?: string;
  result?: vault.ResultRecord;
  outcome: Outcome;
  uncertain?: boolean;
  operation?: string;
  cancelPending?: boolean;
  progress?: number;
};
type Control = {
  id: string; email: string; operation: string; credentials?: Credential;
  job?: string; action: "rotate" | "verify"; state: string; outcome: Outcome;
  cancelled: boolean; submitting: boolean; result?: vault.ResultRecord; retryOf?: string;
  network?: { network_mode: "direct" | "pool"; proxy_pool_version: string };
};
function SecretInput({
  label,
  value,
  onChange,
  placeholder,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  disabled?: boolean;
}) {
  const [show, setShow] = useState(false);
  const [touched, setTouched] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const id = React.useId();
  const parsed = value ? parseSingle(value) : undefined;
  const invalid = touched && parsed?.error;
  return (
    <div className="field">
      <div className="field-heading">
        <Label htmlFor={id}>{label}</Label>
        {value && <Button type="button" variant="plain" size="sm" className="clear-input"
          disabled={disabled} onClick={() => { onChange(""); setShow(false); setTouched(false); inputRef.current?.focus(); }}>
          <X size={13} /> 清空
        </Button>}
      </div>
      <div className="relative">
        <Input
          ref={inputRef}
          id={id}
          aria-label={label}
          autoComplete="off"
          spellCheck={false}
          type={show ? "text" : "password"}
          value={value}
          placeholder={placeholder}
          disabled={disabled}
          aria-invalid={Boolean(invalid)}
          aria-describedby={parsed ? `${id}-hint` : undefined}
          onChange={(e) => onChange(e.target.value)}
          onBlur={() => setTouched(true)}
          className="pr-12"
        />
        <Button
          type="button"
          variant="plain"
          size="icon"
          aria-label={show ? `隐藏${label}` : `显示${label}`}
          aria-pressed={show}
          disabled={disabled}
          className="eye"
          onClick={() => setShow(!show)}
        >
          {show ? <EyeOff size={17} /> : <Eye size={17} />}
        </Button>
      </div>
      {parsed && <div id={`${id}-hint`} className={`input-hint ${parsed.credential ? "valid" : invalid ? "invalid" : ""}`} aria-live="polite">
        {parsed.credential ? <><CheckCircle2 size={13} /> 格式已识别</> : invalid || "账号---密码---2FA密钥"}
      </div>}
    </div>
  );
}
function App() {
  const [scheduler] = useState(() => new TaskQueue(1));
  const [appearance, setAppearance] = useState<Appearance>(readAppearance);
  useEffect(() => applyAppearance(appearance), [appearance]);
  const [caps, setCaps] = useState<any>(null),
    [connected, setConnected] = useState(false),
    [access, setAccess] = useState(""),
    [tab, setTab] = useState("single"),
    [single, setSingle] = useState(""),
    [bulk, setBulk] = useState(""),
    [authorized, setAuthorized] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false),
    [importing, setImporting] = useState(false),
    [dragging, setDragging] = useState(false),
    [unlocking, setUnlocking] = useState(false),
    [addingRetries, setAddingRetries] = useState(false),
    [confirm, setConfirm] = useState(false),
    [confirmRetry, setConfirmRetry] = useState<Row | null>(null),
    [clearCandidate, setClearCandidate] = useState<vault.ResultRecord | null>(null),
    [confirmClearAll, setConfirmClearAll] = useState(false),
    [clearingSaved, setClearingSaved] = useState(false),
    [proxyDialogOpen, setProxyDialogOpen] = useState(false),
    [rows, setRows] = useState<Row[]>([]),
    [saved, setSaved] = useState<vault.ResultRecord[]>([]),
    [selectedSaved, setSelectedSaved] = useState<string[]>([]),
    [shown, setShown] = useState<string[]>([]),
    [filter, setFilter] = useState<TaskFilter>("all");
  const queue = useRef<Credential[]>([]),
    queuedNetwork = useRef<NetworkRoute>({ network_mode: "direct", proxy_pool_version: "" }),
    controls = useRef(new Map<string, Control>()),
    activeRuns = useRef(0),
    launching = useRef(new Set<string>()),
    addingRetryBatch = useRef(false),
    savedRevision = useRef(0),
    clearingResults = useRef(false),
    running = useRef(false),
    exportPasswords = useRef(new Map<string, string>());
  const startButtonRef = useRef<HTMLButtonElement>(null);
  const confirmFocusRef = useRef<HTMLButtonElement | null>(null);
  const clearButtonRef = useRef<HTMLButtonElement | null>(null);
  const clearAllButtonRef = useRef<HTMLButtonElement>(null);
  const savedCardRef = useRef<HTMLDivElement>(null);
  const batchInputRef = useRef<HTMLTextAreaElement>(null);
  const uploadDepth = useRef(0);
  const parsed = parseLines(bulk),
    validRows = parsed.filter((p) => p.credential),
    invalid = parsed.filter((p) => p.error);
  const enabled = Boolean(caps?.enabled && window.isSecureContext);
  const proxyPool = useProxyPool(caps, connected, busy);
  const [lightSnow, setLightSnow] = useLightSnow();
  useEffect(() => scheduler.setLimit(proxyPool.limit), [scheduler, proxyPool.limit]);
  useEffect(() => {
    const expired = () => setConnected(false);
    window.addEventListener("mfa-session-expired", expired);
    return () => window.removeEventListener("mfa-session-expired", expired);
  }, []);
  useEffect(() => {
    api("/capabilities")
      .then(setCaps)
      .catch(() => setError("暂时无法连接服务"));
    api("/session")
      .then((d) => {
        setCsrf(d.csrf);
        setConnected(true);
      })
      .catch(() => {});
    vault
      .list()
      .then(setSaved)
      .catch(() => {});
    const unload = (e: BeforeUnloadEvent) => {
      if (running.current) {
        e.preventDefault();
        e.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", unload);
    return () => window.removeEventListener("beforeunload", unload);
  }, []);
  const patch = (id: string, data: Partial<Row>) =>
    setRows((current) =>
      current.map((r) => {
        if (r.id !== id) return r;
        const updated = { ...r, ...data };
        return { ...updated, progress: taskProgress(updated.stage, updated.state, updated.outcome, r.progress) };
      }),
    );
  const refreshSaved = async () => {
    const version = ++savedRevision.current;
    const records = await vault.list();
    if (version === savedRevision.current) setSaved(records);
  };
  useEffect(() => {
    const ids = new Set(saved.map(record => record.id));
    setSelectedSaved(current => current.filter(id => ids.has(id)));
  }, [saved]);
  const downloadBlob = (content: string) => {
    const url = URL.createObjectURL(
      new Blob([content], { type: "text/plain;charset=utf-8" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = `keyshift-success-${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setNotice("已发起下载");
  };
  const download = async (records: vault.ResultRecord[]) => {
    try {
      const pasted = [...parseLines(bulk), parseSingle(single)]
        .flatMap(row => row.credential ? [row.credential] : []);
      const complete = records.filter(record => record.state === "verified").map(record => {
        const retained = exportPasswords.current.get(record.id);
        const matches = pasted.filter(c => c.email.toLowerCase() === record.email.toLowerCase());
        const passwords = new Set(matches.map(c => c.password));
        const password = retained ?? (passwords.size === 1 ? matches[0].password : record.password);
        return { ...record, password };
      });
      const text = credentialText(complete);
      // Backfill old records only when a known password was provided; never rotate again.
      await Promise.all(complete.filter(record => records.find(original => original.id === record.id)?.password !== record.password).map(record => vault.save(record)));
      await refreshSaved();
      downloadBlob(text);
    } catch (error) {
      setError((error as Error).message);
    }
  };
  const toggleShown = (id: string) => setShown(current => current.includes(id) ? current.filter(value => value !== id) : [...current, id]);
  async function importFile(file: File) {
    if (busy || importing || !enabled) return;
    setImporting(true);
    setError("");
    try { setBulk(await readCredentialFile(file)); }
    catch (error) { setError((error as Error).message); }
    finally { setImporting(false); }
  }
  async function unlock() {
    if (unlocking || !access) return;
    setUnlocking(true);
    try {
      setError("");
      const d = await api("/session", "POST", { access_key: access });
      setCsrf(d.csrf);
      setConnected(true);
      setAccess("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setUnlocking(false);
    }
  }
  async function prepare() {
    if (clearingResults.current) return;
    setError("");
    if (!proxyPool.ready || proxyPool.working) { setError(proxyPool.allowDirect ? "请先填写代理，或开启本机直连" : "请先填写代理池"); return; }
    if (!enabled || !connected) {
      setError("请先使用安全连接并解锁访问");
      return;
    }
    let credentials: Credential[] = [];
    if (tab === "single") {
      const parsed = parseSingle(single);
      if (!parsed.credential) {
        setError(parsed.error ?? "请粘贴一条完整凭证");
        return;
      }
      credentials = [parsed.credential];
    } else {
      if (invalid.length || !validRows.length) {
        setError("请先修正导入格式，至少需要一条有效账号");
        return;
      }
      credentials = validRows.map((r) => r.credential!);
    }
    if (!authorized) {
      setError("请先确认账号操作授权");
      return;
    }
    try {
      await vault.preflight();
      queuedNetwork.current = await proxyPool.prepareNetwork();
      queue.current = credentials;
      confirmFocusRef.current = startButtonRef.current;
      setConfirm(true);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  function beginRun() {
    activeRuns.current++;
    running.current = true;
    setBusy(true);
  }
  function endRun() {
    activeRuns.current--;
    running.current = activeRuns.current > 0;
    setBusy(running.current);
  }
  function clearCredential(control: Control) {
    if (control.credentials) {
      control.credentials.password = "";
      control.credentials.totp_secret = "";
      control.credentials = undefined;
    }
  }
  async function watch(control: Control) {
    const jobId = control.job!;
    // A submission response can be lost before executeRow receives the job ID.
    // Reattaching by operation ID must retain the password needed for TXT export.
    if (control.credentials) exportPasswords.current.set(control.id, control.credentials.password);
    let result = control.result;
    await consume(jobId, async (event) => {
      control.state = event.state;
      patch(control.id, { stage: event.stage ?? "stopped", state: event.state, message: event.message });
      if (event.type === "secret") {
        result = { id: control.id, email: control.email, new_secret: event.new_secret,
          password: control.credentials?.password ?? result?.password ?? exportPasswords.current.get(control.id),
          factor_id: event.factor_id, state: event.state, job_id: jobId,
          receipt: event.receipt, created_at: new Date().toISOString() };
        await vault.save(result);
        control.result = result;
        // Do not keep an old TOTP for a task that has crossed the mutation boundary.
        if (control.credentials) control.credentials.totp_secret = result.new_secret;
        patch(control.id, { result });
        await refreshSaved();
        await api(`/jobs/${jobId}/receipt`, "POST", { receipt: event.receipt });
      }
      if (event.type === "done") {
        if (event.state === "unchanged") exportPasswords.current.delete(control.id);
        const outcome: Outcome = event.outcome ?? (event.state === "verified" ? "success" :
          ["cancelled", "verification_cancelled"].includes(event.code) ? "cancelled" : "failed");
        control.outcome = outcome;
        if (!result) result = await vault.get(control.id);
        if (result) {
          result = { ...result, password: control.credentials?.password ?? result.password ?? exportPasswords.current.get(control.id), job_id: jobId, state: event.state, message: event.message,
            outcome: outcome as vault.ResultRecord["outcome"], code: event.code, action: control.action };
          await vault.save(result);
          control.result = result;
          await refreshSaved();
        }
        patch(control.id, { outcome, result, uncertain: false, cancelPending: false });
        if (outcome === "success" || outcome === "cancelled") clearCredential(control);
        if (outcome === "success") await api(`/jobs/${jobId}`, "DELETE").catch(() => {});
      }
    });
  }
  async function executeRow(control: Control) {
    if (control.cancelled) return;
    try {
      for (let attempt = 0; attempt < 600; attempt++) {
        if (control.cancelled) {
          control.outcome = "cancelled";
          clearCredential(control);
          patch(control.id, { outcome: "cancelled", stage: "stopped", cancelPending: false, message: "未开始，已取消" });
          return;
        }
        control.submitting = true;
        try {
          const data = await admission.submit(token => api(control.retryOf ? `/jobs/${control.retryOf}/retry` : "/jobs", "POST", {
            ...control.network,
            ...control.credentials, operation_id: control.operation, storage_ready: true, authorized: true,
            action: control.action, factor_id: control.result?.factor_id ?? "",
            initial_state: control.state === "enabled_unverified" ? "enabled_unverified" : "activation_unknown",
            slot_token: token,
          }), () => control.cancelled, () => patch(control.id, { stage: "queued", message: "等待执行名额…" }));
          control.job = data.id;
          break;
        } catch (error) {
          if (error instanceof ApiError && ["busy", "slot_expired"].includes(error.code)) {
            control.submitting = false;
            patch(control.id, { message: "等待执行名额…" });
            await new Promise(resolve => setTimeout(resolve, 1000));
            continue;
          }
          // A verification-only retry is safe after the old in-memory job expires.
          if (control.action === "verify" && control.retryOf && error instanceof ApiError && error.code === "job_not_found") {
            control.retryOf = undefined;
            continue;
          }
          throw error;
        } finally {
          control.submitting = false;
        }
      }
      if (!control.job) throw new ApiError("queue_timeout", "等待超时，本任务未提交");
      patch(control.id, { job: control.job, stage: control.action === "verify" ? "verifying" : "authenticating" });
      if (control.cancelled) await api(`/jobs/${control.job}/cancel`, "POST").catch(() => {});
      await watch(control);
    } catch (error) {
      if (error instanceof AdmissionError && error.code === "cancelled_before_submit") {
        control.outcome = "cancelled";
        clearCredential(control);
        patch(control.id, { outcome: "cancelled", stage: "stopped", cancelPending: false, message: error.message });
        return;
      }
      const certainRejection = !control.job && error instanceof ApiError &&
        ["queue_timeout", "admission_queue_full", "disabled", "invalid_input", "account_busy", "rate_limited", "unsafe_retry", "job_not_found", "access_denied", "session_expired", "csrf_rejected", "proxy_required", "proxy_pool_changed", "direct_forbidden"].includes(error.code)
        || (!control.job && error instanceof AdmissionError);
      control.outcome = "failed";
      patch(control.id, { outcome: "failed", stage: "stopped", uncertain: !certainRejection,
        state: control.state, message: (error as Error).message, cancelPending: false });
    }
  }
  async function start() {
    if (running.current || clearingResults.current) return;
    if (!proxyPool.ready || proxyPool.working) { setError("网络出口已变化，请检查代理输入后开始"); return; }
    beginRun();
    setSingle(""); setBulk("");
    for (const control of controls.current.values()) clearCredential(control);
    controls.current.clear();
    const items = queue.current.map(credentials => {
      const id = crypto.randomUUID();
      const control: Control = { id, email: credentials.email, operation: crypto.randomUUID(), credentials,
        action: "rotate", state: "unchanged", outcome: "running", cancelled: false, submitting: false, network: { ...queuedNetwork.current } };
      controls.current.set(id, control);
      return control;
    });
    queue.current = [];
    setRows(items.map(c => ({ id: c.id, email: c.email, operation: c.operation, stage: "queued", state: "unchanged", outcome: "running", progress: 0 })));
    setFilter("all");
    taskPage.setPage(1);
    try { await Promise.all(items.map(control => scheduler.enqueue(() => executeRow(control)))); }
    finally { endRun(); }
  }
  async function cancelRow(id: string) {
    const control = controls.current.get(id);
    if (!control || control.outcome !== "running" || control.cancelled) return;
    control.cancelled = true;
    patch(id, { cancelPending: true, message: "正在请求取消…" });
    if (!control.job && !control.submitting) {
      control.outcome = "cancelled";
      clearCredential(control);
      patch(id, { outcome: "cancelled", stage: "stopped", cancelPending: false, message: "未开始，已取消" });
      return;
    }
    if (control.job) {
      try {
        const response = await api(`/jobs/${control.job}/cancel`, "POST");
        if (!response.done) patch(id, { message: response.deferred
          ? "已开始变更，先保存并启用新密钥，再停止后续验证" : "正在安全取消…" });
      } catch {
        control.cancelled = false;
        patch(id, { cancelPending: false, message: "取消请求未确认，可以重新取消；任务仍在核对" });
      }
    }
  }
  async function cancel() {
    await Promise.all([...controls.current.keys()].map(cancelRow));
  }
  function credentialsFor(row: Row): Credential | undefined {
    const candidates = [...parseLines(bulk), parseSingle(single)]
      .flatMap(item => item.credential ? [item.credential] : [])
      .filter(item => item.email.toLowerCase() === row.email.toLowerCase());
    if (candidates.length) {
      if (new Set(candidates.map(item => JSON.stringify([item.password, item.totp_secret]))).size === 1) return { ...candidates[0] };
      return;
    }
    const retained = controls.current.get(row.id)?.credentials;
    if (retained) return { ...retained };
    const password = exportPasswords.current.get(row.id) ?? row.result?.password;
    if (password && row.result) return { email: row.email, password, totp_secret: row.result.new_secret };
  }
  async function retryRow(row: Row, confirmed = false, storageReady = false) {
    if (clearingResults.current || !connected || launching.current.has(row.id) || controls.current.get(row.id)?.outcome === "running") return;
    const action = retryAction(row.state, row.uncertain);
    if (action === "check") { await resumeRow(row); return; }
    if (!proxyPool.ready) { setError("请先检查代理输入或本机直连设置"); return; }
    if (action === "none") { setError("当前变更阶段不能自动重试，请保留新密钥并人工核对"); return; }
    const credentials = credentialsFor(row);
    if (!credentials) { setError("请重新粘贴该账号的原始凭证，再点击这一行的重试；不要点开始更换"); return; }
    if (action === "verify") {
      if (!row.result) { setError("尚未取得新密钥，请先核对任务"); return; }
      credentials.totp_secret = row.result.new_secret;
    } else if (!confirmed) {
      setConfirmRetry(row); setConfirm(true); return;
    }
    launching.current.add(row.id);
    beginRun();
    try {
      if (!storageReady) await vault.preflight();
      const network = await proxyPool.prepareNetwork();
      const control: Control = { id: row.id, email: row.email, operation: crypto.randomUUID(), credentials,
        action, state: action === "verify" ? (row.state === "enabled_unverified" ? row.state : "activation_unknown") : "unchanged", outcome: "running",
        result: row.result, retryOf: row.job, cancelled: false, submitting: false, network };
      controls.current.set(row.id, control);
      const updated: Row = { ...row, job: undefined,
        operation: control.operation, stage: "queued", state: control.state, outcome: "running",
        progress: taskProgress("queued", control.state, "running"),
        uncertain: false, cancelPending: false, message: action === "verify" ? "仅验证新密钥，不再更换" : "重新执行更换" };
      setRows(current => current.some(item => item.id === row.id) ? current.map(item => item.id === row.id ? updated : item) : [...current, updated]);
      await scheduler.enqueue(() => executeRow(control));
    } catch (error) { setError((error as Error).message); }
    finally { launching.current.delete(row.id); endRun(); }
  }
  function canQueueRetry(row: Row) {
    if (row.outcome !== "failed" || launching.current.has(row.id) || controls.current.get(row.id)?.outcome === "running") return false;
    const action = retryAction(row.state, row.uncertain);
    return (action === "rotate" || (action === "verify" && Boolean(row.result))) && Boolean(credentialsFor(row));
  }
  async function retryFailed() {
    if (clearingResults.current || !connected || addingRetryBatch.current) return;
    addingRetryBatch.current = true;
    setAddingRetries(true);
    try {
      await vault.preflight();
      const candidates = rows.filter(canQueueRetry);
      // Original account consent and rotation confirmation also cover the failed
      // attempt. The explicit batch retry click queues only known-safe actions.
      for (const row of candidates) void retryRow(row, true, true);
      if (candidates.length) setNotice(`已将 ${candidates.length} 个失败任务加入队列`);
    } catch (error) { setError((error as Error).message); }
    finally { addingRetryBatch.current = false; setAddingRetries(false); }
  }
  async function resumeRow(row: Row) {
    if (clearingResults.current || !connected || launching.current.has(row.id) || controls.current.get(row.id)?.outcome === "running") return;
    launching.current.add(row.id);
    beginRun();
    const control: Control = controls.current.get(row.id) ?? {
      id: row.id, email: row.email, operation: row.operation ?? "", action: "verify",
      state: row.state, outcome: "failed", cancelled: false, submitting: false, result: row.result };
    try {
      if (!row.job && !row.operation) throw new Error("任务标识不可用，请保留密钥并人工核对");
      control.job = row.job || (await api(`/operations/${row.operation}`)).id;
      control.outcome = "running"; control.cancelled = false;
      controls.current.set(row.id, control);
      setRows(current => [...current.filter(item => item.id !== row.id), { ...row, stage: "checking", outcome: "running", job: control.job }]);
      await watch(control);
    } catch {
      control.outcome = "failed";
      patch(row.id, { outcome: "failed", uncertain: true, stage: "stopped", message: "任务不可访问，请保留新密钥并核对账户；不要直接再次更换" });
      setError("任务不可访问，请保留新密钥；已启用的结果可使用「重试验证」");
    } finally { launching.current.delete(row.id); endRun(); }
  }
  function resume(record: vault.ResultRecord) {
    const row: Row = { id: record.id, email: record.email, state: record.state, stage: "stopped",
      outcome: record.outcome ?? "failed", result: record, job: record.job_id };
    return retryAction(record.state) === "verify" ? retryRow(row) : resumeRow(row);
  }
  async function clearAllSaved() {
    if (running.current || clearingResults.current || !saved.length) return;
    clearingResults.current = true;
    setClearingSaved(true);
    setConfirmClearAll(false);
    ++savedRevision.current;
    try {
      const ids = new Set(await vault.clearAll());
      for (const id of ids) {
        exportPasswords.current.delete(id);
        const control = controls.current.get(id);
        if (control) clearCredential(control);
        controls.current.delete(id);
      }
      setRows(current => current.filter(row => !ids.has(row.id)));
      setShown(current => current.filter(id => !ids.has(id) && !ids.has(id.replace(/^saved-/, ""))));
      setSelectedSaved(current => current.filter(id => !ids.has(id)));
      setSaved(current => current.filter(record => !ids.has(record.id)));
      await refreshSaved();
      setNotice("已清空本浏览器保存的结果");
      requestAnimationFrame(() => (savedCardRef.current ?? startButtonRef.current)?.focus());
    } catch (error) { setError((error as Error).message); }
    finally { clearingResults.current = false; setClearingSaved(false); }
  }
  const counts = countTasks(rows);
  const success = counts.success, failures = counts.failed, cancelledCount = counts.cancelled;
  const retryableFailures = rows.filter(canQueueRetry).length;
  const displayRows = rows.filter(row => filter === "all" || taskCategory(row) === filter);
  const taskPage = useListPage(displayRows);
  const savedPage = useListPage(saved);
  const selectedSavedRecords = saved.filter(record => selectedSaved.includes(record.id));
  const savedExportRecords = selectedSavedRecords.length ? selectedSavedRecords : saved;
  return (
    <>
      <BackgroundDecor snow={lightSnow} />
      <a className="skip" href="#main">
        跳到主要内容
      </a>
      <main id="main" className="shell">
        <div className="intro">
          <div className="page-title">
            <span className="title-mark" aria-hidden="true"><KeyRound size={20} /></span>
            <div><h1>Keyshift</h1><p className="page-caption">2FA 密钥更换</p></div>
          </div>
          <div className="appearance-controls">
          <SnowControl value={lightSnow} onChange={setLightSnow} />
          <div className="appearance-switch" role="group" aria-label="页面外观">
            {([
              ["light", "纯白"],
              ["dark", "深色"],
            ] as const).map(([value, label]) => (
              <Button
                key={value}
                variant="ghost"
                size="sm"
                aria-pressed={appearance === value}
                onClick={() => setAppearance(value)}
              >
                {value === "light" ? <Sun size={15} /> : <Moon size={15} />}
                {label}
              </Button>
            ))}
          </div>
          </div>
        </div>
        {!caps ? (
          <Alert className="status-banner" role="status">
            <LoaderCircle className="spin" size={18} />
            <AlertDescription>正在检查服务状态…</AlertDescription>
          </Alert>
        ) : !enabled ? (
          <Alert className="status-banner tone-warning" role="status">
            <LockKeyhole size={20} />
              <AlertTitle>
                {window.isSecureContext
                  ? "服务维护中"
                  : "当前连接不安全"}
              </AlertTitle>
              <AlertDescription>
                {window.isSecureContext
                  ? "暂时无法提交账号。"
                  : "请使用 HTTPS 访问后再提交。"}
              </AlertDescription>
          </Alert>
        ) : caps.mode === "demo" ? (
          <Alert className="status-banner tone-warning" role="status">
            <FileText size={20} />
              <AlertTitle>离线演示模式</AlertTitle>
              <AlertDescription>
                请使用测试数据，不会修改真实账号。
              </AlertDescription>
          </Alert>
        ) : null}
        {enabled && !connected && (
          <Card className="access">
            <div>
              <LockKeyhole size={19} />
              <strong>访问口令</strong>
            </div>
            <div className="flex gap-2">
              <Input
                type="password"
                aria-label="服务访问口令"
                placeholder="输入服务访问口令"
                value={access}
                disabled={unlocking}
                onChange={(e) => setAccess(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && unlock()}
              />
              <Button onClick={unlock} disabled={unlocking || !access}>
                {unlocking ? <LoaderCircle className="spin" size={16} /> : <ArrowRight size={16} />}
                {unlocking ? "解锁中" : "解锁"}
              </Button>
            </div>
          </Card>
        )}
        <div className="workspace">
          <div className="left-column">
          <Card className="input-card">
            <div className="card-title">
              <h2 className="import-title"><span className="section-mark" aria-hidden="true"><KeyRound size={16} /></span>导入账号</h2>
              <span className="concurrency-note">最多 {proxyPool.limit} 并发</span>
            </div>
            <Tabs value={tab} onValueChange={setTab}>
              <TabsList aria-label="导入方式">
                <TabsTrigger value="single" disabled={busy || importing}>
                  单个账号
                </TabsTrigger>
                <TabsTrigger value="batch" disabled={busy || importing}>
                  批量导入
                </TabsTrigger>
              </TabsList>
              <TabsContent value="single" className="form-area">
                <SecretInput
                  label="账号凭证"
                  value={single}
                  onChange={setSingle}
                  placeholder="账号---密码---2FA密钥"
                  disabled={busy || !enabled}
                />
              </TabsContent>
              <TabsContent value="batch" className="form-area">
                <label className={`upload ${dragging ? "dragging" : ""}`} aria-disabled={busy || importing || !enabled}
                  onDragEnter={event => {
                    if (!event.dataTransfer.types.includes("Files") || busy || importing || !enabled) return;
                    event.preventDefault(); uploadDepth.current++; setDragging(true);
                  }}
                  onDragOver={event => {
                    if (!event.dataTransfer.types.includes("Files")) return;
                    event.preventDefault(); event.dataTransfer.dropEffect = busy || importing || !enabled ? "none" : "copy";
                  }}
                  onDragLeave={() => { uploadDepth.current = Math.max(0, uploadDepth.current - 1); if (!uploadDepth.current) setDragging(false); }}
                  onDrop={event => {
                    event.preventDefault(); uploadDepth.current = 0; setDragging(false);
                    if (busy || importing || !enabled) return;
                    if (event.dataTransfer.files.length !== 1) { setError("每次请选择一个 TXT 或 TSV 文件"); return; }
                    void importFile(event.dataTransfer.files[0]);
                  }}>
                  <span className="upload-icon" aria-hidden="true">
                    {importing ? <LoaderCircle size={20} className="spin" /> : <Upload size={20} />}
                  </span>
                  <span>
                    <strong>{importing ? "正在读取…" : dragging ? "松开即可导入" : "拖入 TXT，或选择文件"}</strong>
                    <small>最多 50 条 · 256 KiB</small>
                  </span>
                  <input
                    type="file"
                    aria-label="选择账号文件"
                    accept=".txt,.tsv"
                    disabled={busy || importing || !enabled}
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) void importFile(f);
                      e.target.value = "";
                    }}
                  />
                </label>
                <div className="field">
                  <div className="field-heading">
                    <Label htmlFor="batch-credentials">账号凭证 · 每行一条</Label>
                    {bulk && <Button variant="ghost" size="sm" className="clear-input" disabled={busy || importing}
                      onClick={() => { setBulk(""); batchInputRef.current?.focus(); }}><X size={13} /> 清空</Button>}
                  </div>
                  <Textarea
                    ref={batchInputRef}
                    id="batch-credentials"
                    aria-label="批量账号"
                    rows={7}
                    value={bulk}
                    disabled={busy || importing || !enabled}
                    aria-invalid={invalid.length > 0}
                    aria-describedby={invalid.length ? "batch-errors" : bulk ? "batch-summary" : undefined}
                    onChange={(e) => setBulk(e.target.value)}
                    placeholder={"账号---密码---2FA密钥"}
                  />
                </div>
                {bulk && <div className="parse-summary" id="batch-summary" aria-live="polite">
                  <span className={validRows.length ? "valid" : ""}><CheckCircle2 size={13} />{validRows.length} 条有效</span>
                  {invalid.length > 0 && <span className="invalid">{invalid.length} 条待修正</span>}
                </div>}
                {invalid.length > 0 && (
                  <ul className="parse-errors" id="batch-errors">
                    {invalid.slice(0, 5).map((r) => (
                      <li key={r.row}>
                        第 {r.row} 行：{r.error}
                      </li>
                    ))}
                  </ul>
                )}
              </TabsContent>
            </Tabs>
            <div className="consent">
              <Checkbox
                id="account-authorization"
                checked={authorized}
                disabled={busy || !enabled}
                onCheckedChange={(value) => setAuthorized(value === true)}
              />
              <Label htmlFor="account-authorization" className="consent-copy">
                我拥有这些账号或已获得操作授权
              </Label>
            </div>
            <Button
              className="w-full start-action"
              ref={startButtonRef}
              onClick={prepare}
              disabled={busy || clearingSaved || importing || !enabled || !connected || !proxyPool.ready || proxyPool.working}
            >
              {busy && <LoaderCircle size={17} className="spin" />}
              {busy ? "正在处理…" : "开始更换"}
              {!busy && <ArrowRight size={16} className="action-arrow" />}
            </Button>
          </Card>
          <ProxyPoolCard pool={proxyPool} busy={busy} onDialogChange={setProxyDialogOpen} />
          </div>
          <div className="right-column">
            <Card className="results-card" data-processing={busy ? "true" : undefined}>
              <div className="card-title">
                {busy && <ProcessingAccent />}
                <h2 className="results-title"><span className={`activity-dot ${busy ? "active" : success ? "done" : ""}`} aria-hidden="true" />处理结果</h2>
                {rows.length > 0 && (
                  <span className="result-summary">{success} 成功 · {failures} 失败 · {cancelledCount} 取消</span>
                )}
                {busy && (
                  <Button variant="outline" onClick={cancel}>
                    全部取消
                  </Button>
                )}
              </div>
              <div className="result-filter">
                <div role="group" aria-label="任务筛选">
                  {([
                    ["all", "全部"],
                    ["running", "进行中"],
                    ["queued", "队列中"],
                    ["success", "成功"],
                    ["failed", "失败"],
                    ["cancelled", "取消"],
                  ] as const).map(([v, l]) => (
                    <Button
                      key={v}
                      variant="ghost"
                      size="sm"
                      className={filter === v ? "selected" : ""}
                      aria-pressed={filter === v}
                      aria-label={`${l}，${counts[v]} 个任务`}
                      data-task-filter={v}
                      onClick={() => { setFilter(v); taskPage.setPage(1); }}
                    >
                      <span className="filter-label">{l}<span className="filter-count" aria-hidden="true">{counts[v]}</span></span>
                    </Button>
                  ))}
                </div>
                {(filter === "all" || filter === "success") && <Button
                  variant="plain"
                  disabled={!rows.some(r => r.state === "verified" && r.result)}
                  onClick={() => download(rows.flatMap(r => r.result ? [r.result] : []))}
                >
                  <Download size={15} /> 导出成功 TXT
                </Button>}
                {filter === "failed" && <Button variant="plain" onClick={retryFailed}
                  disabled={!connected || addingRetries || retryableFailures === 0}
                  title="按任务阶段重试；状态未知的任务需逐条核对">
                  {addingRetries ? <LoaderCircle size={15} className="spin" /> : <RotateCw size={15} />}
                  重试失败
                </Button>}
              </div>
              <div className="result-content" aria-live="polite">
                {!displayRows.length ? (
                  <div className="empty">
                    <span className="empty-mark" aria-hidden="true"><ListChecks size={23} /></span>
                    <p>
                      {rows.length ? "没有符合条件的任务" : "暂无结果"}
                    </p>
                  </div>
                ) : (
                  taskPage.items.map((r) => (
                    <article className="result-row" data-category={taskCategory(r)} key={r.id}>
                      <div className="row-heading">
                        <span
                          className={
                            r.outcome === "success"
                              ? "status-dot success"
                              : r.outcome === "failed" ? "status-dot failed" : "status-dot"
                          }
                        >
                          {r.outcome === "success" ? (
                            <CheckCircle2 size={18} />
                          ) : r.outcome === "cancelled" ? (
                            <Ban size={18} />
                          ) : r.outcome === "failed" ? (
                            <CircleX size={18} />
                          ) : taskCategory(r) === "queued" ? (
                            <Clock3 size={18} />
                          ) : (
                            <LoaderCircle size={18} className="spin" />
                          )}
                        </span>
                        <strong title={r.email}>{r.email}</strong>
                        <TaskProgress account={r.email} value={r.progress ?? taskProgress(r.stage, r.state, r.outcome)} outcome={r.outcome}
                          status={taskCategory(r) === "queued" ? "队列中" : undefined} />
                      </div>
                      {r.outcome === "failed" && <p className="failure-phase">{failurePhase(r.state, r.uncertain)}</p>}
                      {r.outcome === "cancelled" && r.state !== "unchanged" && <p>新密钥请保留 · {stateName[r.state]}</p>}
                      {r.message && <p>{r.message}</p>}
                      <div className="task-row-meta">
                        <Badge variant="outline" className="task-stage" data-outcome={r.outcome} data-category={taskCategory(r)}>
                          {r.outcome === "cancelled" ? "已取消" : r.outcome === "failed" ? "失败" : r.cancelPending ? "取消中" : stageName[r.stage]}
                        </Badge>
                      <div className="row-actions">
                        {r.outcome === "running" && <Button variant="ghost" size="sm"
                          className="task-cancel"
                          disabled={r.cancelPending} onClick={() => cancelRow(r.id)} aria-label={`取消 ${r.email}`}>
                          <X size={14} />{r.cancelPending ? "取消中" : "取消"}
                        </Button>}
                        {(r.outcome === "failed" || (r.outcome === "cancelled" && retryAction(r.state) === "verify")) && retryAction(r.state, r.uncertain) !== "none" && (
                          <Button variant="outline" size="sm" disabled={!connected} onClick={event => { confirmFocusRef.current = event.currentTarget; void retryRow(r); }}
                            aria-label={`${retryAction(r.state, r.uncertain) === "verify" ? "重试验证" : r.uncertain ? "核对状态" : "失败重试"} ${r.email}`}>
                            <RotateCw size={14} />{retryAction(r.state, r.uncertain) === "verify" ? "重试验证" : r.uncertain ? "核对状态" : "失败重试"}
                          </Button>
                        )}
                      </div>
                      </div>
                      {r.result && (
                        <div className="secret-line">
                          <code>
                            {shown.includes(r.id)
                              ? r.result.new_secret
                              : "•••• •••• •••• ••••"}
                          </code>
                          <Button variant="plain" size="icon"
                            aria-label={shown.includes(r.id) ? "隐藏新密钥" : "显示新密钥"}
                            aria-pressed={shown.includes(r.id)}
                            onClick={() => toggleShown(r.id)}
                          >
                            {shown.includes(r.id) ? <EyeOff size={17} /> : <Eye size={17} />}
                          </Button>
                          <CopyButton value={r.result.new_secret} label="复制新密钥" copiedLabel="新密钥已复制" />
                        </div>
                      )}
                    </article>
                  ))
                )}
              </div>
              <ListPagination label="任务" page={taskPage.page} pageCount={taskPage.pageCount}
                pageSize={taskPage.pageSize} total={taskPage.total}
                onPageChange={taskPage.setPage} onPageSizeChange={taskPage.setPageSize} />
            </Card>
        {saved.length > 0 && (
          <Card className="saved-card" ref={savedCardRef} tabIndex={-1}>
            <div className="card-title">
              <div>
                <h2>
                  已保存结果{" "}
                  <span className="count">{saved.length}</span>
                </h2>
              </div>
              <div className="saved-toolbar">
                <Button ref={clearAllButtonRef} variant="plain" className="clear-saved" disabled={busy || clearingSaved}
                  title={busy ? "请先结束本页任务" : "清空本浏览器保存的全部结果"} onClick={() => setConfirmClearAll(true)}>
                  {clearingSaved ? <LoaderCircle size={16} className="spin" /> : <Trash2 size={16} />} 清空结果
                </Button>
                <Button variant="plain" disabled={selectedSavedRecords.length === saved.length}
                  title="选择所有分页的已保存结果" onClick={() => setSelectedSaved(saved.map(record => record.id))}>
                  <ListChecks size={16} /> 全选
                </Button>
                {selectedSavedRecords.length > 0 && <Button variant="plain" onClick={() => setSelectedSaved([])}>
                  取消选择（{selectedSavedRecords.length}）
                </Button>}
                <Button variant="plain" className="saved-export" disabled={!savedExportRecords.some(r => r.state === "verified")} onClick={() => download(savedExportRecords)}>
                  <Download size={16} /> {selectedSavedRecords.length ? `导出选中 TXT（${savedExportRecords.filter(r => r.state === "verified").length}）` : "导出成功 TXT"}
                </Button>
              </div>
            </div>
            {savedPage.items.map((r) => (
              <div className="saved-entry" key={r.id}>
              <div className="saved-row" data-selected={selectedSaved.includes(r.id) ? "true" : undefined}>
                <Label className="saved-account">
                  <span className="saved-select-target">
                    <Checkbox checked={selectedSaved.includes(r.id)} aria-label={`选择已保存结果 ${r.email}`}
                      onCheckedChange={checked => setSelectedSaved(current => checked === true
                        ? current.includes(r.id) ? current : [...current, r.id]
                        : current.filter(id => id !== r.id))} />
                  </span>
                  <span>{r.email}</span>
                </Label>
                <Badge variant="secondary" className={r.state === "verified" ? "tone-success" : ""}>{stateName[r.state] ?? r.state}</Badge>
                <div className="flex gap-1">
                  {r.state !== "verified" && (
                    <Button
                      variant="ghost"
                      onClick={() => resume(r)}
                      disabled={controls.current.get(r.id)?.outcome === "running" || !connected}
                    >
                      {retryAction(r.state) === "verify" ? "重试验证" : "核对任务"}
                    </Button>
                  )}
                  <Button
                    variant="plain"
                    size="icon"
                    onClick={() => toggleShown(`saved-${r.id}`)}
                    aria-label={`${shown.includes(`saved-${r.id}`) ? "隐藏" : "查看"}已保存密钥 ${r.email}`}
                    aria-expanded={shown.includes(`saved-${r.id}`)}
                    aria-controls={`saved-secret-${r.id}`}
                  >
                    {shown.includes(`saved-${r.id}`) ? <EyeOff size={16} /> : <Eye size={16} />}
                  </Button>
                  {r.state === "verified" && <Button
                    variant="plain"
                    size="icon"
                    onClick={() => download([r])}
                    aria-label={`导出 ${r.email}`}
                  >
                    <Download size={16} />
                  </Button>}
                  <Button
                    variant="plain"
                    size="icon"
                    disabled={busy || clearingSaved}
                    onClick={event => { clearButtonRef.current = event.currentTarget; setClearCandidate(r); }}
                    aria-label={`清除 ${r.email}`}
                  >
                    <Trash2 size={16} />
                  </Button>
                </div>
              </div>
              {shown.includes(`saved-${r.id}`) && <div className="secret-line saved-secret" id={`saved-secret-${r.id}`}>
                <code>{r.new_secret}</code>
                <CopyButton value={r.new_secret} label={`复制已保存密钥 ${r.email}`} copiedLabel={`已复制 ${r.email}`} />
              </div>}
              </div>
            ))}
            <ListPagination label="结果" page={savedPage.page} pageCount={savedPage.pageCount}
              pageSize={savedPage.pageSize} total={savedPage.total}
              onPageChange={savedPage.setPage} onPageSizeChange={savedPage.setPageSize} />
          </Card>
        )}
          </div>
        </div>
      </main>
      <FeedbackDialog open={Boolean(error || notice) && !confirm && !confirmClearAll && !clearCandidate && !proxyDialogOpen}
        message={error || notice} error={Boolean(error)} onClose={() => { setError(""); setNotice(""); }} />
      <Confirm
        open={confirm}
        onReturnFocus={() => { const target = confirmFocusRef.current; if (target?.isConnected && !target.disabled) target.focus(); else startButtonRef.current?.focus(); }}
        onOpenChange={(v) => {
          setConfirm(v);
          if (!v) { queue.current = []; setConfirmRetry(null); }
        }}
        onConfirm={() => {
          setConfirm(false);
          if (confirmRetry) { const row = confirmRetry; setConfirmRetry(null); void retryRow(row, true); }
          else void start();
        }}
      />
      <ClearResultConfirm
        all
        open={confirmClearAll}
        disabled={busy || clearingSaved}
        onOpenChange={setConfirmClearAll}
        onReturnFocus={() => { (clearAllButtonRef.current ?? startButtonRef.current)?.focus(); }}
        onConfirm={() => { void clearAllSaved(); }}
      />
      <ClearResultConfirm
        open={Boolean(clearCandidate)}
        disabled={busy || clearingSaved}
        onReturnFocus={() => { if (clearButtonRef.current?.isConnected) clearButtonRef.current.focus(); }}
        onOpenChange={open => { if (!open) setClearCandidate(null); }}
        onConfirm={() => {
          const record = clearCandidate;
          if (!record || running.current || clearingResults.current) return;
          void (async () => {
            try {
              await vault.remove(record.id);
              exportPasswords.current.delete(record.id);
              const control = controls.current.get(record.id);
              if (control) clearCredential(control);
              controls.current.delete(record.id);
              setRows(current => current.filter(row => row.id !== record.id));
              setShown(current => current.filter(id => id !== record.id && id !== `saved-${record.id}`));
              await refreshSaved();
              requestAnimationFrame(() => (savedCardRef.current ?? startButtonRef.current)?.focus());
            } catch (error) { setError((error as Error).message); }
          })();
        }}
      />
    </>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
