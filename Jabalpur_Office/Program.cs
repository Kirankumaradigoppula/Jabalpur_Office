using System.Text;
using Jabalpur_Office.Data;
using Jabalpur_Office.Filters;
using Jabalpur_Office.ServiceCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Jabalpur_Office.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
//builder.Services.AddSwaggerGen();

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "Jabalpur API", Version = "v1" });

    // ✅ Add JWT Authentication to Swagger
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Please insert JWT token into field (without 'Bearer ' prefix)",
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement {
    {
        new Microsoft.OpenApi.Models.OpenApiSecurityScheme
        {
            Reference = new Microsoft.OpenApi.Models.OpenApiReference
            {
                Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                Id = "Bearer"
            }
        },
        new string[] {}
    }});
});


builder.Services.Configure<StorageSettings>(
    builder.Configuration.GetSection("StorageSettings"));

// ✅ Add this: Register DbContext with connection string --Kiran
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"))
);

//Enable CORS Kiran 
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader()
              .WithExposedHeaders("Content-Disposition")); // 👈 Needed for file downloads
              
});

//Dependency Injection
builder.Services.AddScoped<IsssCore, sssCore>(); //Kiran

//Kiran  JWT Authentication
builder.Services.AddScoped<JwtTokenHelper>();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})

.AddJwtBearer(options =>
{
    var jwtSettings = builder.Configuration.GetSection("JwtSettings");
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]))
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();





// ✅ Set base path for virtual directory (IIS: /Jabalapur)
app.UsePathBase("/Jabalpur");



// ✅ Multiple-user Basic Auth for Swagger
var swaggerUsers = new Dictionary<string, string>
{
    
    { "dhruval", "8980818059" },
    { "shravan", "9737544479" },
    { "kiran", "8099824067" }
};

// Track last access time by IP (you can replace with cookie/session for real apps)
var lastAccessByIP = new Dictionary<string, DateTime>();
var swaggerTimeoutMinutes = 10;

app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/swagger"))
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        // Check auth header
        string authHeader = context.Request.Headers["Authorization"];
        if (authHeader != null && authHeader.StartsWith("Basic "))
        {
            var encoded = authHeader.Substring("Basic ".Length).Trim();
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var parts = decoded.Split(':');
            if (parts.Length == 2)
            {
                var username = parts[0];
                var password = parts[1];
                
                if (swaggerUsers.TryGetValue(username, out var expectedPassword) && expectedPassword == password)
                {
                    //Start Its For Time Limit
                    if (!lastAccessByIP.TryGetValue(ip, out var lastAccess) || DateTime.UtcNow - lastAccess > TimeSpan.FromMinutes(swaggerTimeoutMinutes))
                    {
                        // Expired, force re-authentication
                        lastAccessByIP[ip] = DateTime.UtcNow;
                        context.Response.Headers["WWW-Authenticate"] = "Basic realm=\"Swagger UI\"";
                        context.Response.StatusCode = 401;
                        await context.Response.WriteAsync("Session expired. Re-login required.");
                        return;
                    }

                    // Update last access time and allow
                    lastAccessByIP[ip] = DateTime.UtcNow;

                    // ✅ Disable caching (prevents browser reusing auth)
                    context.Response.Headers["Cache-Control"] = "no-store";
                    context.Response.Headers["Pragma"] = "no-cache";
                    context.Response.Headers["Expires"] = "0";

                    //End Its For Time Limit

                    await next();
                    return;
                }
            }
        }
        // Unauthenticated
        context.Response.Headers["WWW-Authenticate"] = "Basic realm=\"Swagger UI\"";
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Unauthorized Swagger access.");
        return;
    }

    await next();
});

// ✅ Configure Swagger with correct base path
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/Jabalpur/swagger/v1/swagger.json", "Jabalpur API v1");
    c.RoutePrefix = "swagger"; // Makes Swagger UI available at /Jabalapur/swagger
});



// Use CORS
app.UseCors("AllowAll"); //Kiran
//Middleware order matters
app.UseHttpsRedirection();

app.UseAuthentication(); //Without it, the app won’t decode JWT tokens for incoming requests.

app.UseStaticFiles();  // enables wwwroot  // For Image Folder

app.UseMiddleware<JwtMiddleware>(); //22082025

app.UseAuthorization();

app.MapControllers();

app.Run();

public class JwtMiddleware
{
    private readonly RequestDelegate _next;

    public JwtMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        // If request already failed authorization, handle response
        if (context.Response.StatusCode == StatusCodes.Status401Unauthorized)
        {
            await HandleUnauthorizedResponse(context);
            return;
        }

        await _next(context);

        // After executing next middleware, check if token expired
        if (context.Response.StatusCode == StatusCodes.Status401Unauthorized)
        {
            await HandleUnauthorizedResponse(context);
        }
    }

    private static async Task HandleUnauthorizedResponse(HttpContext context)
    {
        context.Response.ContentType = "application/json";
        var response = new
        {
            statusCode = 401,
            message = "Unauthorized or token expired",
            loginStatus = ""
        };

        await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(response));
    }
}