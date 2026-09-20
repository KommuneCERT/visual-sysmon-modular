// Promise API over the engine worker. The worker (and the 4 MB wasm) is only
// started the first time something needs it.
let worker = null, seq = 0;
const pending = new Map();
const listeners = new Set();
export const engineStatus = { state: "idle", error: "" }; // idle | loading | ready | error

function start() {
  if (worker) return worker;
  engineStatus.state = "loading";
  notify();
  worker = new Worker(new URL("./engine-worker.js", import.meta.url));
  worker.onmessage = e => {
    const { id, result } = e.data;
    if (engineStatus.state !== "ready") { engineStatus.state = "ready"; notify(); }
    const p = pending.get(id);
    if (p) { pending.delete(id); p(result); }
  };
  worker.onerror = e => {
    engineStatus.state = "error"; engineStatus.error = e.message || "engine failed to start";
    notify();
    for (const [id, p] of pending) { pending.delete(id); p({ ok: false, error: engineStatus.error }); }
  };
  return worker;
}
function notify() { for (const l of listeners) l(engineStatus); }
export function onEngineStatus(fn) { listeners.add(fn); return () => listeners.delete(fn); }

export function call(fn, arg) {
  const w = start();
  const id = ++seq;
  return new Promise(resolve => { pending.set(id, resolve); w.postMessage({ id, fn, arg }); });
}
export const engine = {
  warmup: () => call("version", {}),
  merge: req => call("merge", req),
  validate: req => call("validate", req),
  analyze: req => call("analyze", req),
  coverage: req => call("coverage", req),
  diff: req => call("diff", req),
  format: req => call("format", req),
};
