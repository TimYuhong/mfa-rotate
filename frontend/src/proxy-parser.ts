export type ProxyParse = { proxies: string[]; errors: { line: number; message: string }[]; duplicates: number };
const protocols = new Set(["http:", "https:", "socks5:", "socks5h:"]);
const encode = (value: string) => encodeURIComponent(value).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

export function normalizeProxy(value: string): string {
  if (!value || value.length > 2048 || /[\x00-\x20\x7f]/.test(value)) throw new Error("格式不正确");
  let text = value.includes("://") ? value : `socks5://${value}`;
  const split = text.indexOf("://"), scheme = text.slice(0, split), rest = text.slice(split + 3);
  if (!rest.includes("@") && !rest.startsWith("[") && rest.split(":").length >= 4) {
    const [host, port, user, ...password] = rest.split(":");
    text = `${scheme}://${encode(user)}:${encode(password.join(":"))}@${host}:${port}`;
  }
  const url = new URL(text);
  if (!protocols.has(url.protocol) || !url.hostname || url.search || url.hash || (url.pathname && url.pathname !== "/")) throw new Error("格式不正确");
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  const port = Number(url.port || (url.protocol === "https:" ? 443 : url.protocol === "http:" ? 80 : 1080));
  if (!Number.isInteger(port) || port < 1 || port > 65535 || host.includes("%")) throw new Error("端口或地址不正确");
  const user = decodeURIComponent(url.username), password = decodeURIComponent(url.password);
  if (/[\x00-\x1f\x7f]/.test(user + password) || (!user && password)) throw new Error("凭据格式不正确");
  return `${url.protocol}//${user ? `${encode(user)}:${encode(password)}@` : ""}${host}:${port}`;
}

export function parseProxyLines(text: string): ProxyParse {
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/).map(line => line.trim());
  const result: ProxyParse = { proxies: [], errors: [], duplicates: 0 }, seen = new Set<string>();
  if (lines.filter(Boolean).length > 50) return { ...result, errors: [{ line: 0, message: "最多 50 条代理" }] };
  lines.forEach((line, index) => {
    if (!line) return;
    try {
      const proxy = normalizeProxy(line);
      if (seen.has(proxy)) result.duplicates++;
      else { seen.add(proxy); result.proxies.push(proxy); }
    } catch { result.errors.push({ line: index + 1, message: "请使用代理 URL 或 主机:端口:用户名:密码" }); }
  });
  if (new TextEncoder().encode(JSON.stringify({ proxies: result.proxies })).length > 65536)
    result.errors.push({ line: 0, message: "代理配置不能超过 64 KiB" });
  return result;
}
