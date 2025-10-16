using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices; // Required for P/Invoke
using System.Threading;
using System.Threading.Tasks;

namespace Worm
{
    class Program
    {
        // --- P/Invoke definitions for WNetAddConnection2 ---
        // (This allows us to call a native Windows API function)

        [DllImport("mpr.dll", CharSet = CharSet.Auto)]
        public static extern int WNetAddConnection2(
            [In] NETRESOURCE lpNetResource,
            [In] string lpPassword,
            [In] string lpUsername,
            [In] int dwFlags);

        [DllImport("mpr.dll", CharSet = CharSet.Auto)]
        public static extern int WNetCancelConnection2(
            [In] string lpName,
            [In] int dwFlags,
            [In] bool fForce);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class NETRESOURCE
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

        // Constants for WNetAddConnection2
        public const int RESOURCETYPE_DISK = 0x1;
        public const int CONNECT_UPDATE_PROFILE = 0x1;
        public const int NO_ERROR = 0; // Equivalent to ERROR_SUCCESS

        // Error codes from WinError.h (just a few common ones)
        public const int ERROR_ACCESS_DENIED = 5;
        public const int ERROR_LOGON_FAILURE = 1326;
        public const int ERROR_INVALID_PASSWORD = 86;


        // --- SMB Login Credentials ---
        const string SmbUsername = "user"; // Replace with your actual SMB username
        const string SmbPassword = "user"; // Replace with your actual SMB password
        const string SmbShareName = "share"; // The name of the share you want to try to access (e.g., "VMShare")

        static async Task Main(string[] args)
        {
            Console.Title = "Local Network IP & SMB Scanner";
            Console.WriteLine("Starting IP Range and SMB Scan...");
            Console.WriteLine("-----------------------------------");

            string baseIpAddress = GetLocalIpAddress();
            if (string.IsNullOrEmpty(baseIpAddress))
            {
                Console.WriteLine("Could not determine local IP address. Please enter a base IP (e.g., 192.168.1.0):");
                baseIpAddress = Console.ReadLine();
            }

            string networkPrefix = GetNetworkPrefix(baseIpAddress);

            if (string.IsNullOrEmpty(networkPrefix))
            {
                Console.WriteLine("Invalid base IP address. Exiting.");
                Console.ReadKey();
                return;
            }

            Console.WriteLine($"Scanning network: {networkPrefix}.1 - {networkPrefix}.254 for active hosts and SMB shares.");
            Console.WriteLine($"Attempting SMB login with Username: '{SmbUsername}', Password: '{SmbPassword}' on share '\\\\<IP>\\{SmbShareName}'");
            Console.WriteLine("This might take a moment...");

            int maxConcurrentOperations = 50;
            using (SemaphoreSlim semaphore = new SemaphoreSlim(maxConcurrentOperations))
            {
                var tasks = new List<Task>();
                List<string> activeIps = new List<string>(); // To store active IPs for potential later use if needed

                for (int i = 1; i < 255; i++)
                {
                    string ipToScan = $"{networkPrefix}.{i}";

                    await semaphore.WaitAsync(); // Wait asynchronously for a slot

                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            if (await PingIpAddress(ipToScan))
                            {
                                lock (activeIps) // Protect shared list
                                {
                                    activeIps.Add(ipToScan);
                                }
                                // If ping is successful, attempt SMB connection
                                await TrySmbConnection(ipToScan);
                            }
                        }
                        finally
                        {
                            semaphore.Release(); // Release the semaphore slot
                        }
                    }));
                }

                await Task.WhenAll(tasks); // Wait for all tasks to complete asynchronously
            }

            Console.WriteLine("\n-----------------------------------");
            Console.WriteLine("Scan complete. Press any key to exit.");
            Console.ReadKey();
        }

        static string GetLocalIpAddress()
        {
            try
            {
                string hostName = Dns.GetHostName();
                IPHostEntry ipEntry = Dns.GetHostEntry(hostName);

                foreach (IPAddress ip in ipEntry.AddressList)
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                    {
                        Console.WriteLine($"Local IP Address detected: {ip.ToString()}");
                        return ip.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting local IP: {ex.Message}");
            }
            return null;
        }

        static string GetNetworkPrefix(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return null;

            string[] octets = ipAddress.Split('.');
            if (octets.Length == 4)
            {
                return $"{octets[0]}.{octets[1]}.{octets[2]}";
            }
            return null;
        }

        // Modified PingIpAddress to return bool
        static async Task<bool> PingIpAddress(string ipAddress)
        {
            using (Ping pinger = new Ping())
            {
                try
                {
                    PingReply reply = await pinger.SendPingAsync(ipAddress, 1000); // 1-second timeout

                    if (reply.Status == IPStatus.Success)
                    {
                        Console.WriteLine($"[ACTIVE] IP: {ipAddress} - Latency: {reply.RoundtripTime} ms");
                        return true;
                    }
                    else
                    {
                        // Console.WriteLine($"[INACTIVE] IP: {ipAddress} - Status: {reply.Status}");
                        return false;
                    }
                }
                catch (PingException)
                {
                    // Console.WriteLine($"[ERROR] IP: {ipAddress} - Ping Exception");
                    return false;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] IP: {ipAddress} - {ex.Message}");
                    return false;
                }
            }
        }

        static async Task TrySmbConnection(string ipAddress)
        {
            // Note: SMB connection attempts can be slow and may block if a server is unresponsive.
            // Adjust maxConcurrentOperations accordingly if you experience issues.

            string remoteSharePath = $"\\\\{ipAddress}\\{SmbShareName}";
            string localDriveLetter = null; // We don't need to map a drive, just connect

            NETRESOURCE nr = new NETRESOURCE
            {
                dwType = RESOURCETYPE_DISK,
                lpRemoteName = remoteSharePath,
                lpLocalName = localDriveLetter // Can be null for direct connection without drive mapping
            };

            int result = -1;
            try
            {
                // WNetAddConnection2 can take time if the target is slow or unavailable.
                // We're wrapping it in Task.Run to keep it off the main async path and allow concurrency.
                result = await Task.Run(() =>
                    WNetAddConnection2(nr, SmbPassword, SmbUsername, CONNECT_UPDATE_PROFILE));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SMB ERROR] IP: {ipAddress} - Exception calling WNetAddConnection2: {ex.Message}");
                return;
            }


            if (result == NO_ERROR)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[SMB SUCCESS] IP: {ipAddress} - Successfully connected to share '{SmbShareName}'!");
                Console.ResetColor();

                // It's good practice to disconnect if we just wanted to check connectivity
                // WNetCancelConnection2(remoteSharePath, CONNECT_UPDATE_PROFILE, false); // Optional: Disconnect immediately
            }
            else
            {
                string errorMessage = GetSmbErrorMessage(result);
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[SMB FAILED] IP: {ipAddress} - Share '{SmbShareName}' - Error Code: {result} ({errorMessage})");
                Console.ResetColor();
            }
        }

        // Helper to get a more readable error message for WNet errors
        static string GetSmbErrorMessage(int errorCode)
        {
            switch (errorCode)
            {
                case NO_ERROR: return "Success";
                case ERROR_ACCESS_DENIED: return "Access Denied (share permissions or user account issue)";
                case ERROR_LOGON_FAILURE: return "Logon Failure (incorrect username or password)";
                case ERROR_INVALID_PASSWORD: return "Invalid Password (for the given username)";
                case 67: return "Network Name Not Found (share not available or machine name/IP is wrong)";
                case 53: return "Network Path Not Found (machine not reachable or share doesn't exist)";
                case 1203: return "No network provider accepted the given network path";
                default: return $"Unknown Error Code: {errorCode}";
            }
        }
    }
}