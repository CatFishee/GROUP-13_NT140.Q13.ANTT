
var builder = WebApplication.CreateBuilder(args);

// --- ADDED: Force the application to use its own directory as the base path ---
// This ensures it always finds the 'wwwroot' folder next to the .exe
builder.Host.UseContentRoot(AppContext.BaseDirectory);


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