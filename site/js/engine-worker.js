// Web Worker hosting the Go/WASM engine so merges never block the UI thread.
importScripts("vendor/wasm_exec.js");
const go = new Go();
const ready = new Promise(r => { self.__sysmonModularReady = r; });
const wasmUrl = "../wasm/sysmon-modular.wasm";
async function instantiate() {
  const resp = fetch(wasmUrl);
  try { return await WebAssembly.instantiateStreaming(resp, go.importObject); }
  catch { // wrong MIME type or no streaming support – fall back to a buffer
    const buf = await (await fetch(wasmUrl)).arrayBuffer();
    return WebAssembly.instantiate(buf, go.importObject);
  }
}
const boot = instantiate().then(({ instance }) => { go.run(instance); return ready; });

self.onmessage = async e => {
  const { id, fn, arg } = e.data;
  try {
    await boot;
    const api = self.sysmonModular;
    if (!api || typeof api[fn] !== "function") throw new Error(`unknown engine function ${fn}`);
    self.postMessage({ id, result: api[fn](arg) });
  } catch (err) {
    self.postMessage({ id, result: { ok: false, error: String(err && err.message || err) } });
  }
};
