import { describe, it, expect } from "vitest";
import { normalizeProxy, parseProxyLines } from "./proxy-parser";

describe("proxy input", () => {
  it("defaults provider input to SOCKS5 and preserves credential case and colons", () => {
    expect(normalizeProxy("gateway.example:3010:UsEr:p:a:ss")).toBe("socks5://UsEr:p%3Aa%3Ass@gateway.example:3010");
  });
  it.each(["http", "https", "socks5", "socks5h"])("retains explicit %s and encoded credentials", scheme => {
    expect(normalizeProxy(`${scheme}://UsEr:p%40ss%3Aword@gateway.example:3010`)).toBe(`${scheme}://UsEr:p%40ss%3Aword@gateway.example:3010`);
  });
  it("deduplicates without merging different session usernames", () => {
    const result = parseProxyLines("gateway.example:3010:A:p\nsocks5://A:p@gateway.example:3010\ngateway.example:3010:a:p");
    expect(result.proxies).toHaveLength(2); expect(result.duplicates).toBe(1);
  });
  it.each(["file:///secret", "http://gateway.example:3010/path", "http://gateway.example:3010?x=1", "http://u:p%0d%0a@gateway.example:3010"])("rejects malformed URL without echoing it", value => {
    const result = parseProxyLines(value); expect(result.proxies).toEqual([]); expect(result.errors[0].line).toBe(1);
    expect(JSON.stringify(result.errors)).not.toContain(value);
  });
  it("limits pool size", () => expect(parseProxyLines(Array.from({ length: 51 }, (_, i) => `gateway.example:3010:u${i}:p`).join("\n")).errors[0].message).toContain("50"));
});
