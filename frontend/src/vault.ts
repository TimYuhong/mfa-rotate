export type ResultRecord = {
  id: string;
  email: string;
  password?: string; // Optional for legacy records; stored only inside AES-GCM ciphertext.
  new_secret: string;
  factor_id: string;
  state: string;
  message?: string;
  job_id?: string;
  receipt?: string;
  created_at: string;
  outcome?: "success" | "failed" | "cancelled";
  code?: string;
  action?: "rotate" | "verify";
};
const dbName = "keyshift-local-results-v1";
function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(dbName, 1);
    r.onupgradeneeded = () => {
      r.result.createObjectStore("keys");
      r.result.createObjectStore("results");
    };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(new Error("本机存储不可用"));
  });
}
async function read(store: string, key: IDBValidKey): Promise<any> {
  const d = await db();
  return new Promise((resolve, reject) => {
    const t = d.transaction(store, "readonly");
    const r = t.objectStore(store).get(key);
    let value: any;
    r.onsuccess = () => (value = r.result);
    t.oncomplete = () => {
      d.close();
      resolve(value);
    };
    t.onerror = () => {
      d.close();
      reject(new Error("本机读取失败"));
    };
  });
}
async function write(store: string, key: IDBValidKey, value: any) {
  const d = await db();
  await new Promise<void>((resolve, reject) => {
    const t = d.transaction(store, "readwrite");
    t.objectStore(store).put(value, key);
    t.oncomplete = () => {
      d.close();
      resolve();
    };
    t.onerror = () => {
      d.close();
      reject(new Error("本机保存失败，未确认激活"));
    };
    t.onabort = t.onerror;
  });
}
async function key(): Promise<CryptoKey> {
  const existing = await read("keys", "aes");
  if (existing) return existing;
  const candidate = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const d = await db();
  // Select one key across tabs without overwriting previously used keys.
  return new Promise((resolve, reject) => {
    const t = d.transaction("keys", "readwrite");
    const store = t.objectStore("keys");
    const r = store.get("aes");
    let selected: CryptoKey;
    r.onsuccess = () => {
      selected = r.result ?? candidate;
      if (!r.result) store.put(selected, "aes");
    };
    t.oncomplete = () => {
      d.close();
      resolve(selected);
    };
    t.onerror = () => {
      d.close();
      reject(new Error("本机密钥存储失败"));
    };
    t.onabort = t.onerror;
  });
}
export async function preflight() {
  if (!window.isSecureContext || !crypto.subtle)
    throw new Error("需要可信 HTTPS 或本机环境才能保护密钥");
  const k = await key();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    k,
    new TextEncoder().encode("storage-check"),
  );
  await crypto.subtle.decrypt({ name: "AES-GCM", iv }, k, encrypted);
}
export async function save(record: ResultRecord) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await key(),
    new TextEncoder().encode(JSON.stringify(record)),
  );
  await write("results", record.id, { iv, encrypted });
  const restored = await get(record.id);
  if (restored?.new_secret !== record.new_secret)
    throw new Error("新密钥本机读回核验失败");
  if (record.password !== undefined && restored.password !== record.password)
    throw new Error("账号凭证本机读回核验失败");
}
export async function get(id: string): Promise<ResultRecord | undefined> {
  const v = await read("results", id);
  if (!v) return;
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: v.iv },
    await key(),
    v.encrypted,
  );
  return JSON.parse(new TextDecoder().decode(plain));
}
export async function list(): Promise<ResultRecord[]> {
  const d = await db();
  const ids = await new Promise<IDBValidKey[]>((resolve, reject) => {
    const t = d.transaction("results", "readonly");
    const r = t.objectStore("results").getAllKeys();
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
    t.oncomplete = () => d.close();
  });
  return (await Promise.all(ids.map((id) => get(String(id))))).filter(
    Boolean,
  ) as ResultRecord[];
}
export async function remove(id: string) {
  const d = await db();
  await new Promise<void>((resolve, reject) => {
    const t = d.transaction("results", "readwrite");
    t.objectStore("results").delete(id);
    t.oncomplete = () => {
      d.close();
      resolve();
    };
    t.onerror = () => {
      d.close();
      reject(new Error("清除失败"));
    };
  });
}

/** Clear only this origin's result records atomically; retain the encryption key and preferences. */
export async function clearAll(): Promise<string[]> {
  const d = await db();
  return new Promise((resolve, reject) => {
    const t = d.transaction("results", "readwrite");
    let ids: string[] = [];
    t.oncomplete = () => { d.close(); resolve(ids); };
    const failed = () => { d.close(); reject(new Error("清空失败，结果未清除，请重试")); };
    t.onerror = failed;
    t.onabort = failed;
    try {
      const store = t.objectStore("results");
      const keys = store.getAllKeys();
      keys.onsuccess = () => { ids = keys.result.map(String); };
      store.clear();
    } catch {
      t.abort();
    }
  });
}
