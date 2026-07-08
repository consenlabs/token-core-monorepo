export interface ImKeyStorage {
  getBindKey(seid: string): Promise<string | null>;
  setBindKey(seid: string, encryptedKey: string): Promise<void>;
}

const DB_NAME = "imkey_secure_storage";
const STORE_NAME = "bindings";
const DB_VERSION = 1;

function requestToPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed."));
  });
}

async function openDb(): Promise<IDBDatabase> {
  const request = indexedDB.open(DB_NAME, DB_VERSION);
  request.onupgradeneeded = () => {
    const db = request.result;
    if (!db.objectStoreNames.contains(STORE_NAME)) {
      db.createObjectStore(STORE_NAME, { keyPath: "seid" });
    }
  };
  return requestToPromise(request);
}

export class IndexedDbImKeyStorage implements ImKeyStorage {
  async getBindKey(seid: string): Promise<string | null> {
    const db = await openDb();
    try {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const record = await requestToPromise<{ seid: string; encryptedKey: string } | undefined>(
        store.get(seid)
      );
      return record?.encryptedKey ?? null;
    } finally {
      db.close();
    }
  }

  async setBindKey(seid: string, encryptedKey: string): Promise<void> {
    const db = await openDb();
    try {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      await requestToPromise(store.put({ seid, encryptedKey }));
      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error ?? new Error("IndexedDB transaction failed."));
      });
    } finally {
      db.close();
    }
  }
}
