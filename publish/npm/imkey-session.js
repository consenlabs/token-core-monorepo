const runtimeQueues = new WeakMap();
const deviceQueues = new WeakMap();

function enqueue(queues, key, operation) {
  const previous = queues.get(key) ?? Promise.resolve();
  const result = previous.then(operation);
  const tail = result.catch(() => undefined);
  queues.set(key, tail);
  return result.finally(() => {
    if (queues.get(key) === tail) queues.delete(key);
  });
}

// A wasm runtime owns global binding state, while a device session spans all
// clients using a transport. Neither lock is the transport's single-APDU lock.
export function runDeviceSession(transport, runtime, operation) {
  return enqueue(runtimeQueues, runtime, () =>
    enqueue(deviceQueues, transport, operation)
  );
}
