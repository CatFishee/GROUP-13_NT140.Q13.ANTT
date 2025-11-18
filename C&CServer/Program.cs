// ===================================
// === C&C SERVER (ATTACKER'S VM) ===
// ===================================

var builder = WebApplication.CreateBuilder(args);

// Cấu hình để server lắng nghe trên cổng 8000
builder.WebHost.UseUrls("http://*:8000");


// Đăng ký các dịch vụ cần thiết
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Cấu hình pipeline của HTTP request
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseStaticFiles();

app.UseAuthorization();

app.MapControllers();

app.Run();