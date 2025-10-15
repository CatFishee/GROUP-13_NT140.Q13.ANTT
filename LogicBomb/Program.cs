using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace LogicBomb
{
    internal class Program
    {
        private static readonly string WatchedDir = @"C:\lab_watch";
        private const string TriggerName = "trigger.flag";
        private const string RequiredToken = "ALLOW_TRIGGER";
        private const string MarkerName = "activated.txt";
        private const string ProcessToRun = "test.exe";
        private const int DebounceMs = 1000; // Debounce time (ms)
        private const int FileReadyTimeoutSec = 5;

        private static FileSystemWatcher watcher;
        private static ConcurrentDictionary<string, DateTime> pending = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private static CancellationTokenSource cts = new CancellationTokenSource();
        private static string logFile;
        static void Main(string[] args)
        {
            Console.WriteLine("[LogicBomb] START (lab only) - Press Ctrl+C to stop");
            Directory.CreateDirectory(WatchedDir);
            logFile = Path.Combine(WatchedDir, "logicbomb_log.jsonl");

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

            // background worker: kiểm tra các file đang chờ và xử lý file đã ổn định
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
                // Chỉ theo dõi file có tên là TriggerName
                if (!string.Equals(Path.GetFileName(path), TriggerName, StringComparison.OrdinalIgnoreCase))
                    return;

                pending[path] = DateTime.UtcNow; // cập nhật thời gian nhìn thấy lần cuối
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
                // tạo một dòng json đơn giản (xử lý thủ công các ký tự đặc biệt)
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

                // chờ file sẵn sàng để đọc
                if (!WaitForFileReady(fullPath, TimeSpan.FromSeconds(FileReadyTimeoutSec)))
                {
                    Console.WriteLine("[LogicBomb] File not ready within timeout: " + fullPath);
                    LogEvent("error", fullPath, "not_ready", "timeout waiting for file ready");
                    return;
                }

                // kiểm tra nội dung token
                string content = "";
                try { content = File.ReadAllText(fullPath); }
                catch (Exception ex) { Console.WriteLine("[LogicBomb] Error reading trigger: " + ex.Message); }

                if (!content.Contains(RequiredToken))
                {
                    Console.WriteLine("[LogicBomb] Trigger does not contain a valid token. Skipping.");
                    LogEvent("skipped", fullPath, "invalid_token", null);
                    return;
                }

                // tạo file đánh dấu (marker)
                string markerPath = Path.Combine(WatchedDir, MarkerName);
                File.WriteAllText(markerPath, $"Activated by {TriggerName} at {DateTime.Now:yyyy-MM-dd HH:mm:ss}\r\n");
                Console.WriteLine("[LogicBomb] Creating marker: " + markerPath);

                // tạo thư mục chứa bằng chứng
                string evidenceDir = Path.Combine(WatchedDir, "evidence_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
                Directory.CreateDirectory(evidenceDir);

                // 1) danh sách tiến trình
                try
                {
                    var procs = Process.GetProcesses().OrderBy(p => p.ProcessName).ToArray();
                    using (var sw = new StreamWriter(Path.Combine(evidenceDir, "process_list.txt")))
                    {
                        foreach (var p in procs)
                        {
                            try { sw.WriteLine($"{p.Id}\t{p.ProcessName}\t{p.StartTime.ToString("o")}"); }
                            catch { sw.WriteLine($"{p.Id}\t{p.ProcessName}\t<no start time>"); }
                        }
                    }
                    Console.WriteLine("[LogicBomb] Saving process_list.txt");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[LogicBomb] Error getting process list: " + ex.Message);
                }

                // 2) kết quả lệnh netstat -ano
                try
                {
                    var psi = new ProcessStartInfo("netstat", "-ano")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    var p = Process.Start(psi);
                    string outp = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(2000);
                    File.WriteAllText(Path.Combine(evidenceDir, "netstat_ano.txt"), outp);
                    Console.WriteLine("[LogicBomb] Saving netstat_ano.txt");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[LogicBomb] Error running netstat: " + ex.Message);
                }

                // 3) danh sách file trong thư mục bị giám sát
                try
                {
                    using (var sw = new StreamWriter(Path.Combine(evidenceDir, "watched_dir_listing.txt")))
                    {
                        foreach (var fi in new DirectoryInfo(WatchedDir).GetFiles())
                        {
                            sw.WriteLine($"{fi.Name}\t{fi.Length}\t{fi.CreationTimeUtc:o}\t{fi.LastWriteTimeUtc:o}");
                        }
                    }
                    Console.WriteLine("[LogicBomb] Saving watched_dir_listing.txt");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[LogicBomb] Error listing directory: " + ex.Message);
                }

                // 4) lấy một vài dòng cuối của System Event Log
                try
                {
                    using (var sw = new StreamWriter(Path.Combine(evidenceDir, "system_eventlog_tail.txt")))
                    {
                        var el = new System.Diagnostics.EventLog("System");
                        int tail = 200;
                        int start = Math.Max(0, el.Entries.Count - tail);
                        for (int i = start; i < el.Entries.Count; i++)
                        {
                            var en = el.Entries[i];
                            sw.WriteLine($"{en.TimeGenerated:o}\t{en.EntryType}\t{en.Source}\t{en.Message}");
                        }
                    }
                    Console.WriteLine("[LogicBomb] Saving system_eventlog_tail.txt");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[LogicBomb] Could not read event log: " + ex.Message);
                }

                LogEvent("evidence_saved", fullPath, null, "evidenceDir=" + evidenceDir);

                string exePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ProcessToRun);

                Console.WriteLine($"[LogicBomb] DEBUG: Searching for file at path: {exePath}");

                if (File.Exists(exePath))
                {
                    Console.WriteLine("[LogicBomb] (Optional) Launching " + exePath);
                    try
                    {
                        var psi2 = new ProcessStartInfo
                        {
                            FileName = exePath,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };
                        var p2 = Process.Start(psi2);
                        if (p2 != null)
                            p2.WaitForExit(10000);
                        LogEvent("ran_testexe", fullPath, exePath, null);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[LogicBomb] Error running test.exe: " + ex.Message);
                    }
                }
                else
                {
                    Console.WriteLine("[LogicBomb] test.exe not found. Skipping execution.");
                }

                // di chuyển file trigger để tránh kích hoạt lại
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

                LogEvent("process_end", fullPath, null, "evidenceDir=" + evidenceDir);
                Console.WriteLine("[LogicBomb] Done. Evidence -> " + evidenceDir);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[LogicBomb] HandleTrigger error: " + ex.Message);
                LogEvent("error", fullPath, "exception", ex.Message);
            }
        }

        private static bool WaitForFileReady(string path, TimeSpan timeout)
        {
            Stopwatch sw = Stopwatch.StartNew();
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