using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;


namespace LogicBomb
{
    internal class Program
    {
        // Lưu ý: vẫn là "SAFE MODE" nhưng sẽ KHỞI CHẠY file .exe tuyệt đối nếu thoả điều kiện
        private static readonly string WatchedDir = @"C:\lab_watch";
        private const string TriggerName = "trigger.flag";
        private const string RequiredToken = "ALLOW_TRIGGER";
        private const string MarkerName = "activated.txt";
        private const string PayloadZip = "payload.zip";
        private const string HarmlessMarker = "harmless.marker";
        private static readonly HashSet<string> Whitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "x.exe", "unikey.exe", "Malware.exe", "test.exe" // chỉnh tên file được phép
        };

        // **SỬA TẠI ĐÂY**: đặt đường dẫn tuyệt đối tới Unikey (hoặc bất kỳ .exe hợp lệ bạn muốn chạy)
        private static readonly string AbsoluteExePath = @"C:\An toàn mạng\DoAn\LogicBomb\bin\Debug\test.exe";

        private const int DebounceMs = 1000;
        private const int FileReadyTimeoutSec = 5;
        private const int ExecTimeoutMs = 5000; // chờ 5s, nếu tiến trình GUI không exit thì ta không block

        private static FileSystemWatcher watcher;
        private static ConcurrentDictionary<string, DateTime> pending = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private static CancellationTokenSource cts = new CancellationTokenSource();
        private static string logFile;

        static void Main(string[] args)
        {
            Console.WriteLine("[LogicBomb] START (SAFE MODE) - Press Ctrl+C to stop");
            Directory.CreateDirectory(WatchedDir);
            logFile = Path.Combine(WatchedDir, "logicbomb_safe_log.jsonl");

            watcher = new FileSystemWatcher(WatchedDir)
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

            Console.WriteLine($"[LogicBomb] Watching: {WatchedDir}");
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

                // tạo marker
                string markerPath = Path.Combine(WatchedDir, MarkerName);
                File.WriteAllText(markerPath, $"(SAFE) Activated by {TriggerName} at {DateTime.Now:yyyy-MM-dd HH:mm:ss}\r\n");
                Console.WriteLine("[LogicBomb] Creating marker: " + markerPath);

                // giải nén payload.zip (nếu có) vào sandbox (subfolder)
                string zipPath = Path.Combine(WatchedDir, PayloadZip);
                string sandbox = Path.Combine(WatchedDir, "sandbox_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
                Directory.CreateDirectory(sandbox);

                if (File.Exists(zipPath))
                {
                    try
                    {
                        ZipFile.ExtractToDirectory(zipPath, sandbox);
                        Console.WriteLine("[LogicBomb] Extracted payload.zip to " + sandbox);
                        LogEvent("extracted", zipPath, "extracted_to", sandbox);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[LogicBomb] Error extracting zip: " + ex.Message);
                        LogEvent("error", zipPath, "extract_failed", ex.Message);
                    }
                }
                else
                {
                    Console.WriteLine("[LogicBomb] payload.zip not found in watched dir. Continuing to check absolute path only.");
                    LogEvent("info", fullPath, "no_payload", null);
                }

                // BƯỚC: kiểm tra đường dẫn tuyệt đối và chạy exe (nếu thoả điều kiện)
                try
                {
                    Console.WriteLine("[LogicBomb] Checking absolute path: " + AbsoluteExePath);

                    if (!Path.IsPathRooted(AbsoluteExePath))
                    {
                        Console.WriteLine("[LogicBomb] Provided path is not absolute. Skipping execution.");
                        LogEvent("info", AbsoluteExePath, "not_absolute", null);
                    }
                    else if (!File.Exists(AbsoluteExePath))
                    {
                        Console.WriteLine("[LogicBomb] File does not exist at absolute path: " + AbsoluteExePath);
                        LogEvent("info", AbsoluteExePath, "not_found", null);
                    }
                    else
                    {
                        string fileName = Path.GetFileName(AbsoluteExePath);
                        if (!Whitelist.Contains(fileName))
                        {
                            Console.WriteLine("[LogicBomb] File name not in whitelist: " + fileName + ". Skipping execution.");
                            LogEvent("info", AbsoluteExePath, "not_whitelisted", fileName);
                        }
                        else
                        {
                            // optional: require harmless.marker inside sandbox (to mark payload as safe)
                            string harmlessInSandbox = Path.Combine(sandbox, "payload", HarmlessMarker);
                            if (!File.Exists(harmlessInSandbox))
                            {
                                Console.WriteLine("[LogicBomb] harmless.marker not found in extracted payload. Skipping execution for safety.");
                                LogEvent("info", sandbox, "marker_missing", HarmlessMarker);
                            }
                            else
                            {
                                Console.WriteLine("[LogicBomb] Preconditions OK -> launching: " + AbsoluteExePath);

                                // Start the EXE using UseShellExecute = true so GUI apps (like Unikey) behave normally.
                                var psi = new ProcessStartInfo
                                {
                                    FileName = AbsoluteExePath,
                                    WorkingDirectory = Path.GetDirectoryName(AbsoluteExePath) ?? sandbox,
                                    UseShellExecute = true,
                                    CreateNoWindow = false
                                };

                                try
                                {
                                    var proc = Process.Start(psi);
                                    if (proc != null)
                                    {
                                        // Wait a short time; if app is long-running (like Unikey), we won't block indefinitely.
                                        bool exited = proc.WaitForExit(ExecTimeoutMs);
                                        LogEvent("exec_started", AbsoluteExePath, exited ? "exited" : "running", $"procId={proc.Id}");
                                        Console.WriteLine("[LogicBomb] Started process. PID=" + proc.Id + ", exitedWithinTimeout=" + exited);
                                    }
                                    else
                                    {
                                        Console.WriteLine("[LogicBomb] Process.Start returned null (failed to start).");
                                        LogEvent("error", AbsoluteExePath, "start_failed", null);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine("[LogicBomb] Error starting executable: " + ex.Message);
                                    LogEvent("error", AbsoluteExePath, "start_exception", ex.Message);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[LogicBomb] Error checking/executing absolute path: " + ex.Message);
                    LogEvent("error", AbsoluteExePath, "exec_exception", ex.Message);
                }

                // di chuyển trigger để tránh kích hoạt lại
                try
                {
                    string processed = Path.Combine(WatchedDir, "processed_" + Path.GetFileName(fullPath));
                    File.Move(fullPath, processed);
                    Console.WriteLine("[LogicBomb] Moving trigger to: " + processed);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[LogicBomb] Could not move trigger: " + ex.Message);
                }

                LogEvent("process_end", fullPath, null, null);
                Console.WriteLine("[LogicBomb] Done (safe-run).");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[LogicBomb] HandleTrigger error: " + ex.Message);
                LogEvent("error", fullPath, "exception", ex.Message);
            }
        }

        private static bool WaitForFileReady(string path, TimeSpan timeout)
        {
            var sw = Stopwatch.StartNew();
            while (sw.Elapsed < timeout)
            {
                try
                {
                    using (var fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        return true;
                    }
                }
                catch (IOException)
                {
                    Thread.Sleep(200);
                }
            }
            return false;
        }
    }
}
