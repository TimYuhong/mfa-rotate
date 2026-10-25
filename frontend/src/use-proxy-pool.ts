import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import { clearProxyPool, loadProxyDraft, saveProxyDraft } from "./proxy-vault";
import { parseProxyLines } from "./proxy-parser";

export type ProxyStatus = {
  version: string; count: number; entries: { id: string; endpoint: string }[];
};
export type NetworkRoute = { network_mode: "direct" | "pool"; proxy_pool_version: string };
export type ProxyTestResult = { ok: true; country: string; ip: string; latency_ms: number; selected: number }
  | { ok: false; code: string; message: string; selected?: number };
const directKey = "mfa-rotate-local-direct";
function readDirect() { try { return localStorage.getItem(directKey) !== "false"; } catch { return true; } }

export function useProxyPool(caps: any, connected: boolean, busy: boolean) {
  const [draft, setDraft] = useState(""), [loaded, setLoaded] = useState(false);
  const [working, setWorking] = useState(false), [error, setError] = useState("");
  const [saveState, setSaveState] = useState<"saved" | "saving" | "failed">("saved");
  const [testing, setTesting] = useState(false), [testResult, setTestResult] = useState<ProxyTestResult | null>(null);
  const testPending = useRef(false);
  const [localDirect, setLocalDirect] = useState(readDirect);
  const epoch = useRef(0), revision = useRef(0), writes = useRef<Promise<void>>(Promise.resolve());
  const synced = useRef<{ signature: string; route: NetworkRoute } | null>(null);
  const flight = useRef<{ signature: string; promise: Promise<NetworkRoute> } | null>(null);
  const allowDirect = Boolean(caps?.routing?.allow_direct), direct = allowDirect && localDirect;
  const parsed = parseProxyLines(draft), proxies = parsed.proxies;
  useEffect(() => {
    let alive = true;
    loadProxyDraft().then(value => { if (alive) { setDraft(value); setLoaded(true); } })
      .catch(reason => { if (alive) { setError(reason.message); setLoaded(true); } });
    return () => { alive = false; };
  }, []);
  useEffect(() => {
    epoch.current++;
    synced.current = null;
    flight.current = null;
    setWorking(false);
    setTestResult(null);
    if (connected) setError("");
  }, [connected]);

  const updateDraft = (value: string) => {
    if (!loaded || busy || working || testPending.current) return;
    setTestResult(null);
    setDraft(value); setError(""); setSaveState("saving");
    const current = ++revision.current;
    // Serialize encrypted writes so an older input can never overwrite a newer one.
    const next = writes.current.catch(() => {}).then(async () => {
      if (current !== revision.current) return;
      await saveProxyDraft(value);
      if (current === revision.current) setSaveState("saved");
    });
    writes.current = next;
    void next.catch(reason => { if (current === revision.current) { setSaveState("failed"); setError(reason.message); } });
  };
  const prepareNetwork = async (): Promise<NetworkRoute> => {
    if (testPending.current) throw new Error("请等待代理测试完成");
    if (!connected) throw new Error("请先解锁访问");
    if (direct) return { network_mode: "direct", proxy_pool_version: "" };
    if (!loaded || !proxies.length || parsed.errors.length) throw new Error("请先填写正确的代理格式");
    await writes.current;
    const signature = JSON.stringify(proxies);
    if (synced.current?.signature === signature) return { ...synced.current.route };
    if (flight.current?.signature === signature) return flight.current.promise;
    const generation = epoch.current;
    setWorking(true); setError("");
    const promise = (async () => {
      try {
        const uploaded: ProxyStatus = await api("/proxy-pool", "PUT", { proxies });
        if (generation !== epoch.current) throw new Error("访问会话已变化，请重新开始");
        const route: NetworkRoute = { network_mode: "pool", proxy_pool_version: uploaded.version };
        synced.current = { signature, route };
        return { ...route };
      } catch (reason) { if (generation === epoch.current) setError((reason as Error).message); throw reason; }
      finally { if (generation === epoch.current) { flight.current = null; setWorking(false); } }
    })();
    flight.current = { signature, promise };
    return promise;
  };

  const setDirect = (value: boolean) => {
    if (!allowDirect || busy || working || testPending.current) return;
    setTestResult(null);
    setLocalDirect(value); setError("");
    try { localStorage.setItem(directKey, String(value)); } catch { /* Session preference still works. */ }
  };
  const clear = async () => {
    if (busy || working || !loaded || testPending.current) return;
    setTestResult(null);
    setWorking(true); setError("");
    try {
      await writes.current.catch(() => {});
      await clearProxyPool();
      revision.current++; setDraft(""); setSaveState("saved"); synced.current = null;
      writes.current = Promise.resolve();
      if (connected) await api("/proxy-pool", "DELETE");
    } catch (reason) { setError((reason as Error).message); }
    finally { setWorking(false); }
  };
  const testRandom = async () => {
    if (!loaded || !connected || busy || working || testPending.current || !proxies.length || parsed.errors.length) return;
    testPending.current = true; setTesting(true); setTestResult(null);
    const generation = epoch.current;
    try {
      await writes.current;
      const result: ProxyTestResult = await api("/proxy-pool/test", "POST", { proxies }, 35000);
      if (generation === epoch.current) setTestResult(result);
    } catch (reason) {
      if (generation === epoch.current) setTestResult({ ok: false, code: "request_failed", message: (reason as Error).message || "测试请求未完成" });
    } finally { testPending.current = false; setTesting(false); }
  };
  const ready = direct || (loaded && proxies.length > 0 && !parsed.errors.length && saveState !== "failed");
  return { draft, updateDraft, parsed, proxies, loaded, error, working: working || testing, saveState, direct, allowDirect, setDirect,
    clear, ready, prepareNetwork, testRandom, testing, testResult, canTest: connected && proxies.length > 0 && !parsed.errors.length,
    limit: caps?.max_concurrent ?? 1 };
}
