import { useEffect, useState } from "react";
import { Globe2, LoaderCircle, Shuffle, Trash2 } from "lucide-react";
import { Button, Card, Label, Textarea } from "./ui";
import { Switch } from "./ui/switch";
import { useProxyPool } from "../use-proxy-pool";
import { DialogGlass } from "./dialog-glass";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "./ui/alert-dialog";

export function ProxyPoolCard({ pool, busy, onDialogChange }: { pool: ReturnType<typeof useProxyPool>; busy: boolean; onDialogChange?: (open: boolean) => void }) {
  const [confirmClear, setConfirmClear] = useState(false);
  useEffect(() => { onDialogChange?.(confirmClear); return () => onDialogChange?.(false); }, [confirmClear, onDialogChange]);
  const parsed = pool.parsed, locked = busy || pool.working || !pool.loaded;
  return <Card className="proxy-card" aria-label="代理池">
    <div className="card-title">
      <h2 className="proxy-title"><Globe2 size={16} /> 代理池 <span className="count">{pool.proxies.length}</span></h2>
      {pool.draft && <Button variant="plain" size="icon" disabled={locked} onClick={() => setConfirmClear(true)} aria-label="清空代理池" title="清空代理池"><Trash2 size={16} /></Button>}
    </div>
    {pool.allowDirect && <Label className="proxy-direct">
      <span>本机直连</span><span className="switch-target" title="开启后绕过代理池，沿用系统代理或本机网络">
        <Switch checked={pool.direct} onCheckedChange={pool.setDirect} disabled={locked} aria-label="本机直连" />
      </span>
    </Label>}
    <div className="proxy-editor">
      <Label htmlFor="proxy-lines">代理地址 · 每行一条</Label>
      <Textarea id="proxy-lines" aria-label="代理地址" value={pool.draft} onChange={event => pool.updateDraft(event.target.value)}
        disabled={locked} rows={6} maxLength={65536} autoComplete="off" spellCheck={false}
        placeholder={"主机:端口:用户名:密码（默认 SOCKS5）\nsocks5://用户名:密码@主机:端口\nsocks5h://用户名:密码@主机:端口\nhttp://用户名:密码@主机:端口\nhttps://用户名:密码@主机:端口"} />
      {parsed.errors.length > 0 && <p className="proxy-error" role="alert">{parsed.errors[0].line ? `第 ${parsed.errors[0].line} 行：` : ""}{parsed.errors[0].message}</p>}
      <div className="proxy-tools">
        <span className="proxy-count" role="status">{parsed.proxies.length} 条有效</span>
        <Button variant="ghost" disabled={locked || !pool.canTest} aria-busy={pool.testing} title="随机选一条代理测试 HTTPS 连通性"
          onClick={() => void pool.testRandom()}>
          {pool.testing ? <LoaderCircle size={15} className="spin" /> : <Shuffle size={15} />}
          {pool.testing ? "测试中…" : "随机测试"}
        </Button>
      </div>
      {pool.testResult && <p className={`proxy-test-result ${pool.testResult.ok ? "success" : "failed"}`} role="status"
        aria-label="代理随机测试结果" title={pool.testResult.ok ? `代理 ${pool.testResult.selected} · HTTPS 请求延迟，包含代理建连` : undefined}>
        {pool.testResult.selected ? `第 ${pool.testResult.selected} 条代理 · ` : ""}
        {pool.testResult.ok
          ? `${pool.testResult.country} · ${pool.testResult.ip} · ${pool.testResult.latency_ms} ms`
          : `测试失败 · ${pool.testResult.message}`}
      </p>}
    </div>
    {pool.error && <p className="proxy-error" role="alert">{pool.error}</p>}
    <AlertDialog open={confirmClear} onOpenChange={setConfirmClear}>
      <AlertDialogContent className="glass-dialog max-w-[min(32rem,calc(100vw-2rem))]">
        <DialogGlass />
        <AlertDialogHeader><AlertDialogTitle>清空代理池？</AlertDialogTitle>
          <AlertDialogDescription className="glass-description">仅清除本浏览器的代理配置。</AlertDialogDescription></AlertDialogHeader>
        <AlertDialogFooter className="gap-2"><AlertDialogCancel data-glass-cancel>取消</AlertDialogCancel>
          <AlertDialogAction disabled={locked} className="bg-destructive text-destructive-foreground hover:bg-destructive/90" onClick={() => void pool.clear()}>确认清空</AlertDialogAction></AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  </Card>;
}
