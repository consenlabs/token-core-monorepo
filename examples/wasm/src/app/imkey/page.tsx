"use client";

import { useCallback, useEffect, useState } from "react";
import { createImKeyCore, type ImKeyCore } from "@/lib/imkey-core";

interface LogItem {
  name: string;
  status: "idle" | "running" | "pass" | "fail";
  detail?: string;
}

export default function ImKeyPage() {
  const [core, setCore] = useState<ImKeyCore | null>(null);
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [running, setRunning] = useState(false);
  const [webUsbSupported, setWebUsbSupported] = useState(true);

  useEffect(() => {
    setWebUsbSupported("usb" in navigator);
  }, []);

  const push = (item: LogItem) => {
    setLogs((previous) => {
      const index = previous.findIndex((entry) => entry.name === item.name);
      if (index === -1) return [...previous, item];
      const next = [...previous];
      next[index] = item;
      return next;
    });
  };

  const runStep = useCallback(async (name: string, task: () => Promise<string>) => {
    push({ name, status: "running" });
    try {
      push({ name, status: "pass", detail: await task() });
    } catch (error) {
      push({
        name,
        status: "fail",
        detail: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }, []);

  const runCoreStep = useCallback(
    async (name: string, task: (imkey: ImKeyCore) => Promise<string>) => {
      if (!core) return;
      push({ name, status: "running" });
      try {
        push({ name, status: "pass", detail: await task(core) });
      } catch (error) {
        push({
          name,
          status: "fail",
          detail: JSON.stringify(
            {
              error: error instanceof Error ? error.message : String(error),
              diagnostics: core.diagnostics(),
            },
            null,
            2
          ),
        });
        throw error;
      }
    },
    [core]
  );

  const connect = useCallback(async () => {
    setRunning(true);
    try {
      push({ name: "Init ikc-wasm", status: "running" });
      const imkey = createImKeyCore();
      push({ name: "Init ikc-wasm", status: "pass", detail: "Business facade created" });

      push({ name: "Connect WebUSB", status: "running" });
      const result = await imkey.connect();
      setCore(imkey);
      push({
        name: "Connect WebUSB",
        status: "pass",
        detail: JSON.stringify(result, null, 2),
      });
    } catch (error) {
      push({
        name: "Connect WebUSB",
        status: "fail",
        detail: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setRunning(false);
    }
  }, []);

  const readInfo = useCallback(async () => {
    if (!core) return;
    setRunning(true);
    try {
      await runCoreStep("Get SEID", (imkey) => imkey.getSeid());
      await runCoreStep("Get SN", (imkey) => imkey.getSn());
      await runCoreStep("Get Life Time", (imkey) => imkey.getLifeTime());
      await runCoreStep("Get Device Info", async (imkey) =>
        JSON.stringify(await imkey.getDeviceInfo(), null, 2)
      );
    } catch (error) {
      // The failing step has already been marked by runStep.
    } finally {
      setRunning(false);
    }
  }, [core, runCoreStep]);

  const rawSelect = useCallback(async () => {
    if (!core) return;
    setRunning(true);
    try {
      await runCoreStep("Debug Raw Select ISD", (imkey) => imkey.sendRawApdu("00A4040000"));
    } finally {
      setRunning(false);
    }
  }, [core, runCoreStep]);

  const directRawSelect = useCallback(async () => {
    if (!core) return;
    setRunning(true);
    try {
      await runCoreStep("Debug Direct Raw Select ISD", (imkey) =>
        imkey.sendRawApduDirect("00A4040000")
      );
    } finally {
      setRunning(false);
    }
  }, [core, runCoreStep]);

  const runSecureCheck = useCallback(async () => {
    if (!core) return;
    setRunning(true);
    try {
      push({ name: "Secure Check", status: "running" });
      push({
        name: "Secure Check",
        status: "pass",
        detail: JSON.stringify(await core.secureCheck(), null, 2),
      });
    } catch (error) {
      push({
        name: "Secure Check",
        status: "fail",
        detail: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setRunning(false);
    }
  }, [core]);

  const displayBindCode = useCallback(async () => {
    if (!core) return;
    setRunning(true);
    try {
      push({ name: "Display Bind Code", status: "running" });
      await core.bindDisplayCode();
      push({ name: "Display Bind Code", status: "pass", detail: "Code displayed on device" });
    } catch (error) {
      push({
        name: "Display Bind Code",
        status: "fail",
        detail: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setRunning(false);
    }
  }, [core]);

  const activateDevice = useCallback(async () => {
    if (!core) return;
    setRunning(true);
    try {
      push({ name: "Activate Device", status: "running" });
      push({
        name: "Activate Device",
        status: "pass",
        detail: JSON.stringify(await core.activateDevice(), null, 2),
      });
    } catch (error) {
      push({
        name: "Activate Device",
        status: "fail",
        detail: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setRunning(false);
    }
  }, [core]);

  const checkUpdate = useCallback(async () => {
    if (!core) return;
    setRunning(true);
    try {
      push({ name: "Check Update", status: "running" });
      push({
        name: "Check Update",
        status: "pass",
        detail: JSON.stringify(await core.checkUpdate(), null, 2),
      });
    } catch (error) {
      push({
        name: "Check Update",
        status: "fail",
        detail: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setRunning(false);
    }
  }, [core]);

  return (
    <main className="min-h-screen bg-zinc-950 px-6 py-8 text-zinc-100">
      <div className="mx-auto flex max-w-4xl flex-col gap-6">
        <header className="flex flex-col gap-2">
          <h1 className="text-2xl font-semibold">imKey Core WASM WebUSB</h1>
          <p className="text-sm text-zinc-400">
            WebUSB example for the ikc-wasm business API and async transport integration.
          </p>
        </header>

        <div className="flex flex-wrap gap-3">
          <button
            className="rounded bg-emerald-500 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
            disabled={running}
            onClick={connect}
          >
            Connect imKey
          </button>
          <button
            className="rounded bg-sky-500 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
            disabled={running || !core}
            onClick={readInfo}
          >
            Read Device Info
          </button>
          <button
            className="rounded bg-lime-500 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
            disabled={running || !core}
            onClick={rawSelect}
          >
            Debug Raw Select
          </button>
          <button
            className="rounded bg-lime-300 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
            disabled={running || !core}
            onClick={directRawSelect}
          >
            Debug Direct Raw Select
          </button>
          <button
            className="rounded bg-violet-500 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
            disabled={running || !core}
            onClick={runSecureCheck}
          >
            Secure Check
          </button>
          <button
            className="rounded bg-amber-500 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
            disabled={running || !core}
            onClick={displayBindCode}
          >
            Display Bind Code
          </button>
          <button
            className="rounded bg-rose-500 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
            disabled={running || !core}
            onClick={activateDevice}
          >
            Activate
          </button>
          <button
            className="rounded bg-teal-500 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
            disabled={running || !core}
            onClick={checkUpdate}
          >
            Check Update
          </button>
        </div>

        {!webUsbSupported && (
          <div className="rounded border border-amber-400/40 bg-amber-400/10 p-4 text-sm text-amber-100">
            WebUSB is not available in this browser. Use Chrome or Edge.
          </div>
        )}

        <section className="grid gap-3">
          {logs.map((log) => (
            <article key={log.name} className="rounded border border-zinc-800 bg-zinc-900 p-4">
              <div className="flex items-center justify-between gap-4">
                <h2 className="text-sm font-medium">{log.name}</h2>
                <span className="text-xs uppercase text-zinc-400">{log.status}</span>
              </div>
              {log.detail && (
                <pre className="mt-3 overflow-auto rounded bg-zinc-950 p-3 text-xs text-zinc-300">
                  {log.detail}
                </pre>
              )}
            </article>
          ))}
        </section>
      </div>
    </main>
  );
}
