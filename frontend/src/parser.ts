export type Credential = {
  email: string;
  password: string;
  totp_secret: string;
};
export type Parsed = { row: number; credential?: Credential; error?: string };
export function validate(c: Credential): string | undefined {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(c.email) || c.email.length > 254)
    return "邮箱格式不正确";
  if (!c.password || c.password.length > 512)
    return "密码不能为空或超过 512 字符";
  if (!/^[A-Z2-7]{16,104}$/.test(c.totp_secret))
    return "第三项须为 Base32 密钥，不是 6 位验证码";
}
export function parseSingle(text: string): Parsed {
  const parsed = parseLines(text);
  if (parsed.length !== 1)
    return { row: 1, error: "请粘贴一条账号---密码---2FA密钥，多条请使用批量导入" };
  return parsed[0];
}
export function parseLines(text: string): Parsed[] {
  if (new TextEncoder().encode(text).length > 262144)
    return [{ row: 0, error: "文件不能超过 256 KiB" }];
  const lines = text
    .replace(/^\uFEFF/, "")
    .split(/\r?\n/)
    .filter((l) => l.trim());
  if (lines.length > 50) return [{ row: 0, error: "每批最多 50 条" }];
  const seen = new Set<string>();
  return lines.map((line, i) => {
    let parts: string[] = [];
    if (line.includes("\t")) parts = line.split("\t");
    else if (line.includes("----")) parts = line.split("----");
    else {
      parts = line.split("---");
      if (parts.length === 2) {
        const legacy = line.match(/^([^\s@]+@[^\s@]+?\.[^\s@]+?)--(.*?)---([A-Za-z2-7= ]+)$/);
        if (legacy) parts = legacy.slice(1);
      }
    }
    if (parts.length !== 3)
      return {
        row: i + 1,
        error: "请使用账号---密码---2FA密钥；密码含分隔符时请粘贴三列 TAB",
      };
    const credential = {
      email: parts[0].trim(),
      password: parts[1],
      totp_secret: parts[2].replace(/ /g, "").toUpperCase().replace(/=+$/, ""),
    };
    const error = validate(credential);
    if (error) return { row: i + 1, error };
    const key = credential.email.toLowerCase();
    if (seen.has(key))
      return { row: i + 1, error: "同一批内账号重复，请保留一条" };
    seen.add(key);
    return { row: i + 1, credential };
  });
}
