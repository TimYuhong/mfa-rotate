export async function readCredentialFile(file: Pick<File, "name" | "size" | "text">): Promise<string> {
  if (!/\.(txt|tsv)$/i.test(file.name)) throw new Error("请选择 TXT 或 TSV 文件");
  if (file.size > 262144) throw new Error("文件不能超过 256 KiB");
  try {
    return await file.text();
  } catch {
    throw new Error("文件读取失败，请重新选择或直接粘贴");
  }
}
