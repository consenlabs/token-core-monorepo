export interface ImKeyStorage {
  getBindKey(seid: string): Promise<string | null>;
  setBindKey(seid: string, encryptedKey: string): Promise<void>;
}

export class IndexedDbImKeyStorage implements ImKeyStorage {
  constructor(indexedDb?: IDBFactory);
  getBindKey(seid: string): Promise<string | null>;
  setBindKey(seid: string, encryptedKey: string): Promise<void>;
}
