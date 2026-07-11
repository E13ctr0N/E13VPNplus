import { load, Store } from "@tauri-apps/plugin-store";

const STORE_FILE = "vpn.json";

let storePromise: Promise<Store> | null = null;
let saveQueue: Promise<void> = Promise.resolve();

export function getVpnStore(): Promise<Store> {
  storePromise ??= load(STORE_FILE, { autoSave: false, defaults: {} });
  return storePromise;
}

export function queueVpnStoreSave(update: (store: Store) => Promise<void>): Promise<void> {
  const operation = saveQueue
    .catch(() => {})
    .then(async () => {
      const store = await getVpnStore();
      await update(store);
      await store.save();
    });
  saveQueue = operation;
  return operation;
}
