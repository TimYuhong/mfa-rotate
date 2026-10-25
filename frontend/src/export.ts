import type { ResultRecord } from "./vault";

export function credentialText(
  records: ResultRecord[],
  passwordFor: (record: ResultRecord) => string | undefined = record => record.password,
): string {
  const successful = records.filter(record => record.state === "verified");
  if (!successful.length) throw new Error("暂无验证成功的结果，请先核对未完成任务");
  return successful.map(record => {
    const password = passwordFor(record);
    if (password === undefined || password === "")
      throw new Error("旧结果缺少密码。请粘贴对应凭证后再次导出，将自动补存，无需更换。");
    if ([record.email, password, record.new_secret].some(value => /[\r\n]/.test(value)))
      throw new Error("凭证含换行，无法安全导出为一行文本");
    return `${record.email}---${password}---${record.new_secret}`;
  }).join("\r\n") + "\r\n";
}
