const DB_NAME = "imkey_secure_storage";
const STORE_NAME = "bindings";
const DB_VERSION = 1;

function requestToPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed."));
  });
}

async function openDb(indexedDb) {
  const request = indexedDb.open(DB_NAME, DB_VERSION);
  request.onupgradeneeded = () => {
    const db = request.result;
    if (!db.objectStoreNames.contains(STORE_NAME)) {
      db.createObjectStore(STORE_NAME, { keyPath: "seid" });
    }
  };
  return requestToPromise(request);
}

export class IndexedDbImKeyStorage {
  constructor(indexedDb = globalThis.indexedDB) {
    if (!indexedDb) throw new Error("imkey_indexeddb_not_available");
    this.indexedDb = indexedDb;
  }

  async getBindKey(seid) {
    const db = await openDb(this.indexedDb);
    try {
      const record = await requestToPromise(
        db.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(seid)
      );
      return record?.encryptedKey ?? null;
    } finally {
      db.close();
    }
  }

  async setBindKey(seid, encryptedKey) {
    const db = await openDb(this.indexedDb);
    try {
      const transaction = db.transaction(STORE_NAME, "readwrite");
      await requestToPromise(transaction.objectStore(STORE_NAME).put({ seid, encryptedKey }));
      await new Promise((resolve, reject) => {
        transaction.oncomplete = resolve;
        transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB failed."));
      });
    } finally {
      db.close();
    }
  }
}
