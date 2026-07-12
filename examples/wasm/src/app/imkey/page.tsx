"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { createImKeyCore, type ImKeyCore } from "@/lib/imkey-core";

interface LogItem {
  name: string;
  status: "idle" | "running" | "pass" | "fail";
  detail?: string;
}

interface ApduLog {
  id: number;
  command: string;
  response: string;
  time: string;
  error?: boolean;
}

export default function ImKeyPage() {
  const [core, setCore] = useState<ImKeyCore | null>(null);
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [apduCommand, setApduCommand] = useState("");
  const [apduLogs, setApduLogs] = useState<ApduLog[]>([]);
  const [bindingCode, setBindingCode] = useState("");
  const [signParams, setSignParams] = useState("{\n  \"chainType\": \"ETHEREUM\",\n  \"path\": \"m/44'/60'/0'/0/0\",\n  \"network\": \"MAINNET\",\n  \"input\": {}\n}");
  const [appName, setAppName] = useState("");
  const [nextApduLogId, setNextApduLogId] = useState(1);
  const [running, setRunning] = useState(false);
  const [sendingApdu, setSendingApdu] = useState(false);
  const [webUsbSupported, setWebUsbSupported] = useState(true);
  const apduScrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setWebUsbSupported("usb" in navigator);
  }, []);

  useEffect(() => {
    if (apduScrollRef.current) {
      apduScrollRef.current.scrollTop = apduScrollRef.current.scrollHeight;
    }
  }, [apduLogs]);

  const push = useCallback((item: LogItem) => {
    setLogs((previous) => {
      const index = previous.findIndex((entry) => entry.name === item.name);
      if (index === -1) return [...previous, item];
      const next = [...previous];
      next[index] = item;
      return next;
    });
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

  const runBindCheck = useCallback(async () => {
    if (!core) return;
    setRunning(true);
    try {
      push({ name: "Bind Check", status: "running" });
      push({ name: "Bind Check", status: "pass", detail: await core.bindCheck() });
    } catch (error) {
      push({
        name: "Bind Check",
        status: "fail",
        detail: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setRunning(false);
    }
  }, [core]);

  const runBindAcquire = useCallback(async () => {
    if (!core) return;
    const code = bindingCode.trim().toUpperCase();
    if (!code) return;
    setRunning(true);
    try {
      push({ name: "Bind Acquire", status: "running" });
      push({ name: "Bind Acquire", status: "pass", detail: await core.bindAcquire(code) });
    } catch (error) {
      push({
        name: "Bind Acquire",
        status: "fail",
        detail: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setRunning(false);
    }
  }, [bindingCode, core]);

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

  const signTransaction = useCallback(async () => {
    if (!core) return;
    setRunning(true);
    try {
      const params = JSON.parse(signParams) as unknown;
      push({ name: "Sign Transaction", status: "running" });
      push({
        name: "Sign Transaction",
        status: "pass",
        detail: JSON.stringify(await core.signTx(params), null, 2),
      });
    } catch (error) {
      push({
        name: "Sign Transaction",
        status: "fail",
        detail: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setRunning(false);
    }
  }, [core, push, signParams]);

  const manageApp = useCallback(async (action: "download" | "update" | "delete") => {
    if (!core || !appName.trim()) return;
    setRunning(true);
    const label = `App ${action[0].toUpperCase()}${action.slice(1)}`;
    try {
      push({ name: label, status: "running" });
      const result = action === "download"
        ? await core.appDownload(appName.trim())
        : action === "update"
          ? await core.appUpdate(appName.trim())
          : await core.appDelete(appName.trim());
      push({ name: label, status: "pass", detail: JSON.stringify(result, null, 2) });
    } catch (error) {
      push({
        name: label,
        status: "fail",
        detail: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setRunning(false);
    }
  }, [appName, core, push]);

  const sendApduCommand = useCallback(async () => {
    if (!core || sendingApdu) return;
    const command = apduCommand.trim().replace(/\s+/g, "").toUpperCase();
    if (!command) return;

    setSendingApdu(true);
    const time = new Date().toLocaleTimeString();
    try {
      const response = await core.sendRawApdu(command);
      setApduLogs((previous) => [
        ...previous,
        {
          id: nextApduLogId,
          command,
          response: response.toUpperCase(),
          time,
        },
      ]);
    } catch (error) {
      setApduLogs((previous) => [
        ...previous,
        {
          id: nextApduLogId,
          command,
          response: error instanceof Error ? error.message : String(error),
          time,
          error: true,
        },
      ]);
    } finally {
      setNextApduLogId((previous) => previous + 1);
      setSendingApdu(false);
    }
  }, [apduCommand, core, nextApduLogId, sendingApdu]);

  const clearApduLogs = useCallback(() => {
    setApduLogs([]);
  }, []);

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
            disabled={running || !webUsbSupported}
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
            className="rounded bg-lime-500 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
            disabled={running || !core}
            onClick={runBindCheck}
          >
            Bind Check
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

        <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
          <h2 className="text-sm font-medium">Bind Acquire</h2>
          <div className="mt-4 flex flex-col gap-3 sm:flex-row">
            <input
              className="min-w-0 flex-1 rounded border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm uppercase text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-sky-500"
              maxLength={8}
              placeholder="Enter 8-character bind code"
              value={bindingCode}
              onChange={(event) => setBindingCode(event.target.value.toUpperCase())}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  void runBindAcquire();
                }
              }}
            />
            <button
              className="rounded bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
              disabled={!core || running || bindingCode.trim().length !== 8}
              onClick={runBindAcquire}
            >
              Bind
            </button>
          </div>
        </section>

        <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
          <h2 className="text-sm font-medium">Sign Transaction</h2>
          <textarea
            className="mt-4 min-h-56 w-full resize-y rounded border border-zinc-700 bg-zinc-950 p-3 font-mono text-xs text-zinc-100 outline-none focus:border-sky-500"
            spellCheck={false}
            value={signParams}
            onChange={(event) => setSignParams(event.target.value)}
          />
          <button
            className="mt-3 rounded bg-sky-500 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
            disabled={!core || running || !signParams.trim()}
            onClick={signTransaction}
          >
            Sign
          </button>
        </section>

        <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
          <h2 className="text-sm font-medium">App Management</h2>
          <div className="mt-4 flex flex-col gap-3 sm:flex-row">
            <input
              className="min-w-0 flex-1 rounded border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-sky-500"
              placeholder="App name"
              value={appName}
              onChange={(event) => setAppName(event.target.value)}
            />
            <button
              className="rounded bg-emerald-500 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
              disabled={!core || running || !appName.trim()}
              onClick={() => void manageApp("download")}
            >
              Download
            </button>
            <button
              className="rounded bg-amber-500 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
              disabled={!core || running || !appName.trim()}
              onClick={() => void manageApp("update")}
            >
              Update
            </button>
            <button
              className="rounded bg-rose-500 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
              disabled={!core || running || !appName.trim()}
              onClick={() => void manageApp("delete")}
            >
              Delete
            </button>
          </div>
        </section>

        {!webUsbSupported && (
          <div className="rounded border border-amber-400/40 bg-amber-400/10 p-4 text-sm text-amber-100">
            WebUSB is not available in this browser. Use Chrome or Edge.
          </div>
        )}

        <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <h2 className="text-sm font-medium">APDU Console</h2>
            {apduLogs.length > 0 && (
              <button
                className="rounded border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:border-zinc-500 disabled:opacity-50"
                disabled={sendingApdu}
                onClick={clearApduLogs}
              >
                Clear
              </button>
            )}
          </div>

          <div className="mt-4 flex flex-col gap-3 sm:flex-row">
            <input
              className="min-w-0 flex-1 rounded border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-sky-500"
              placeholder="Enter APDU hex command"
              value={apduCommand}
              onChange={(event) => setApduCommand(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  void sendApduCommand();
                }
              }}
            />
            <button
              className="rounded bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
              disabled={!core || sendingApdu || !apduCommand.trim()}
              onClick={sendApduCommand}
            >
              {sendingApdu ? "Sending..." : "Send"}
            </button>
          </div>

          <div
            ref={apduScrollRef}
            className="mt-4 h-64 overflow-auto rounded bg-zinc-950 p-3 font-mono text-xs"
          >
            {apduLogs.length === 0 ? (
              <div className="flex h-full items-center justify-center text-zinc-600">
                Ready for commands...
              </div>
            ) : (
              <div className="grid gap-3">
                {apduLogs.map((log) => (
                  <div key={log.id} className="border-b border-zinc-800 pb-3 last:border-0">
                    <div className="mb-2 flex items-center justify-between gap-3 text-[11px] text-zinc-500">
                      <span>
                        #{log.id} · {log.time}
                      </span>
                      <span className={log.error ? "text-rose-400" : "text-emerald-400"}>
                        {log.error ? "ERROR" : "OK"}
                      </span>
                    </div>
                    <div className="break-all leading-relaxed text-sky-300">
                      <span className="text-zinc-500">&gt;&gt; </span>
                      {log.command}
                    </div>
                    <div className={log.error ? "break-all leading-relaxed text-rose-300" : "break-all leading-relaxed text-emerald-300"}>
                      <span className="text-zinc-500">&lt;&lt; </span>
                      {log.response}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

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
