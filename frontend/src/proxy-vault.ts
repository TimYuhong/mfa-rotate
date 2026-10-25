/** Separate encrypted preferences database: clearing results never clears the proxy pool. */
const dbName = "keyshift-local-proxy-pool-v1";
async function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(dbName, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore("keys");
      request.result.createObjectStore("settings");
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error("代理配置存储不可用"));
  });
}
async function read(store: string, id: string): Promise<any> {
  const database = await db();
  return new Promise((resolve, reject) => {
    const tx = database.transaction(store, "readonly"), request = tx.objectStore(store).get(id);
    tx.oncomplete = () => { database.close(); resolve(request.result); };
    tx.onabort = tx.onerror = () => { database.close(); reject(new Error("代理配置读取失败")); };
  });
}
async function key(): Promise<CryptoKey> {
  const candidate = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const database = await db();
  return new Promise((resolve, reject) => {
    const tx = database.transaction("keys", "readwrite"), store = tx.objectStore("keys"), request = store.get("aes");
    let selected: CryptoKey;
    request.onsuccess = () => { selected = request.result ?? candidate; if (!request.result) store.put(selected, "aes"); };
    tx.oncomplete = () => { database.close(); resolve(selected); };
    tx.onabort = tx.onerror = () => { database.close(); reject(new Error("代理加密密钥不可用")); };
  });
}
export async function loadProxyDraft(): Promise<string> {
  const record = await read("settings", "pool");
  if (!record) return "";
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: record.iv }, await key(), record.encrypted);
    const value: unknown = JSON.parse(new TextDecoder().decode(plain));
    // Preserve the old encrypted list while moving to automatic raw-input saving.
    if (Array.isArray(value) && value.length <= 50 && value.every(item => typeof item === "string")) return value.join("\n");
    if (typeof value !== "string" || value.length > 65536) throw new Error();
    return value;
  } catch { throw new Error("代理配置无法解密，请重新填写"); }
}
async function write(value?: { iv: Uint8Array; encrypted: ArrayBuffer }) {
  const database = await db();
  await new Promise<void>((resolve, reject) => {
    const tx = database.transaction("settings", "readwrite"), store = tx.objectStore("settings");
    tx.oncomplete = () => { database.close(); resolve(); };
    tx.onabort = tx.onerror = () => { database.close(); reject(new Error("代理配置保存失败")); };
    try { if (value) store.put(value, "pool"); else store.delete("pool"); }
    catch { tx.abort(); }
  });
}
export async function saveProxyDraft(draft: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await key(), new TextEncoder().encode(JSON.stringify(draft)));
  await write({ iv, encrypted });
  if (await loadProxyDraft() !== draft) throw new Error("代理配置读回核验失败");
}
export const clearProxyPool = () => write();
