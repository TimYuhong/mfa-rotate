import { describe, expect, it, vi } from "vitest";
import { readCredentialFile } from "./import-file";

describe("credential file import", () => {
  it("preserves credentials exactly", async () => {
    const text = "user@example.com\t password \tJBSWY3DPEHPK3PXP\r\n";
    expect(await readCredentialFile({ name: "accounts.txt", size: 80, text: async () => text })).toBe(text);
  });
  it("accepts TSV and case-insensitive extensions", async () => {
    expect(await readCredentialFile({ name: "accounts.TSV", size: 1, text: async () => "a" })).toBe("a");
  });
  it("rejects unrelated files without reading them", async () => {
    const text = vi.fn();
    await expect(readCredentialFile({ name: "accounts.json", size: 10, text })).rejects.toThrow("TXT 或 TSV");
    expect(text).not.toHaveBeenCalled();
  });
  it("rejects oversized files without reading them", async () => {
    const text = vi.fn();
    await expect(readCredentialFile({ name: "accounts.txt", size: 262145, text })).rejects.toThrow("256 KiB");
    expect(text).not.toHaveBeenCalled();
  });
  it("allows the exact byte limit", async () => {
    expect(await readCredentialFile({ name: "accounts.txt", size: 262144, text: async () => "data" })).toBe("data");
  });
  it("turns read failures into an actionable message", async () => {
    await expect(readCredentialFile({ name: "accounts.txt", size: 1, text: async () => { throw new Error("private filename"); } })).rejects.toThrow("文件读取失败");
  });
});
