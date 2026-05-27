using Jabalpur_Office.Data;
using Jabalpur_Office.Filters;
using Jabalpur_Office.Models;
using Jabalpur_Office.ServiceCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Text;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// -------------------- Services --------------------
builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle

// Swagger with JWT and XML comments
builder.Services.AddEndpointsApiExplorer();

// ✅ Add this: Register DbContext with connection string --Kiran
// DbContext
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"))
);

//Dependency Injection
builder.Services.AddScoped<IsssCore, sssCore>();

//Kiran  JWT Authentication
builder.Services.AddScoped<JwtTokenHelper>();
builder.Services.AddHttpContextAccessor();

builder.Services.Configure<StorageSettings>(
    builder.Configuration.GetSection("StorageSettings"));

// Report settings from DB or appsettings
builder.Services.Configure<SsrsSettings>(
    builder.Configuration.GetSection("SSRS"));

builder.Services.AddScoped<IExportService, ExportService>();

//Enable CORS Kiran 
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader()
              .SetIsOriginAllowed(_ => true)
              .WithExposedHeaders("Content-Disposition",
               "X-StatusCode",
               "X-Message",
               "X-BatchId",
               "X-TotalRecords",
               "X-SuccessRecords",
               "X-FailedRecords"

              )); // 👈 Needed for file downloads

    /*options.AddPolicy("AllowSpecificOrigins", policy =>
    {
        policy.WithOrigins(
          "https://digitechkonnect.com",
          "https://www.digitechkonnect.com",
          "https://digitechkonnect.com/TestJabalpur",
          "https://digitechkonnect.com/Jabalpur",
          "http://localhost:7056",
          "http://localhost:3000"
        )
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials()
        .SetIsOriginAllowed(_ => true)
         .WithExposedHeaders("Content-Disposition"); // 👈 Needed for file downloads
    });*/

});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    var jwtSettings = builder.Configuration.GetSection("JwtSettings");
    string? secretKey = jwtSettings["SecretKey"];
    if (string.IsNullOrEmpty(secretKey))
    {
        throw new InvalidOperationException("JWT SecretKey is not configured.");
    }
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ClockSkew = TimeSpan.Zero, // 🔥 IMPORTANT
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
    };
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = async context =>
        {
            if (context.Exception is SecurityTokenExpiredException)
            {
                var httpContext = context.HttpContext;
                var scopeFactory = httpContext.RequestServices.GetRequiredService<IServiceScopeFactory>();
                using var scope = scopeFactory.CreateScope();
                var core = scope.ServiceProvider.GetRequiredService<IsssCore>();

                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Authorization token missing");
                    return;
                }

                string token = authHeader.Substring("Bearer ".Length).Trim();

                if (!string.IsNullOrEmpty(token))
                {
                    var pMessage = new SqlParameter("@pMessage", SqlDbType.NVarChar, 500)
                    {
                        Direction = ParameterDirection.Output
                    };

                    var pStatusCode = new SqlParameter("@pStatusCode", SqlDbType.Int)
                    {
                        Direction = ParameterDirection.Output
                    };

                    SqlParameter[] sqlParams =
                    {
                        new SqlParameter("@pTOKEN", token),
                        new SqlParameter("@pFLAG", "TOKEN_EXPIRED"),
                        pMessage,
                        pStatusCode
                    };

                    DataTable dt = core.ExecProcDt("ReactCrudPortalLoginHistoryDetails", sqlParams);

                    int statusCode = (pStatusCode.Value != DBNull.Value) ? Convert.ToInt32(pStatusCode.Value) : 0;
                    string message = pMessage.Value?.ToString() ?? "";


                    if (statusCode == 200)
                    {
                        context.Response.StatusCode = 401;
                        await context.Response.WriteAsync(
                            string.IsNullOrEmpty(message)
                            ? "Session expired or logged out from another device."
                            : message
                        );


                        var responseObject = new
                        {
                            dataList = new object[] { new { } },
                            extraData = new { },
                            pager = (object?)null,
                            statusCode = 401,
                            message = "Your session has expired. Please login again.",
                            loginStatus = "TOKEN_EXPIRED"
                        };

                        await httpContext.Response.WriteAsync(
                            System.Text.Json.JsonSerializer.Serialize(responseObject)
                        );
                    }

                    // ⛔ Stop further processing
                    context.Fail("JWT token expired");
                }


            }
        }
    };
});

builder.Services.AddAuthorization();

// -------------------- SWAGGER --------------------

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "Jabalpur API", Version = "v1", Description = "Production API for Jabalpur Office" });

    // XML comments
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
        c.IncludeXmlComments(xmlPath);

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

// -------------------- APP --------------------
var app = builder.Build();

// ✅ Configure Swagger with correct base path
app.UseSwagger();

app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("v1/swagger.json", "Jabalpur API v1");
    c.RoutePrefix = "swagger"; // Makes Swagger UI available at /Jabalapur/swagger
});

//Middleware order matters
app.UseHttpsRedirection();
app.UseStaticFiles();  // enables wwwroot  // For Image Folder
// Use CORS
app.UseCors("AllowAll"); //Kiran
app.UseAuthentication(); //Without it, the app won’t decode JWT tokens for incoming requests.

app.UseMiddleware<JwtMiddleware>(); //22082025

// 🔐 DB Token Validator (skip Swagger)
//app.UseMiddleware<TokenValidatorMiddleware>();
app.UseAuthorization();

app.MapControllers();

app.Run();

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
        string? authHeader = context.Request.Headers["Authorization"];
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


// =====================================================================
// ====================== TOKEN VALIDATOR MIDDLEWARE ====================
// =====================================================================

//Chartgpt Link "https://chatgpt.com/c/691160df-7580-8320-be90-2bc6772230af" --Gujarat pppc

// 👇 Controllers that NEVER need JWT


public class TokenValidatorMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IServiceScopeFactory _scopeFactory;

    public TokenValidatorMiddleware(RequestDelegate next, IServiceScopeFactory scopeFactory)
    {
        _next = next;
        _scopeFactory = scopeFactory;

    }
    private static readonly HashSet<string> SkipControllers =
    new(StringComparer.OrdinalIgnoreCase)
    {
            "ProductApi",
            "SMS"

    };

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {

            // =====================================================
            // 1️⃣ Skip endpoints marked with [AllowAnonymous]
            // =====================================================
            var endpoint = context.GetEndpoint();
            var actionDescriptor = endpoint?.Metadata.GetMetadata<ControllerActionDescriptor>();
            //if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null)
            //{
            //    await _next(context);
            //    return;
            //}

            bool skipAuth =
                endpoint?.Metadata.GetMetadata<IAllowAnonymous>() != null &&
                (actionDescriptor != null &&
                 SkipControllers.Contains(actionDescriptor.ControllerName));

            if (skipAuth)
            {
                await _next(context);
                return;
            }

            // =====================================================
            // 2️⃣ Skip public APIs by path (optional / legacy)
            // =====================================================

            string? path = context.Request.Path.Value?.ToLower();
            // Skip public APIs
            if (path != null && (
                path.Contains("validateUserLoginSeat") || path.Contains("validateuser") || path.Contains("verifyotp")
                 || path.Contains("getotp") || path.Contains("getotpdetails") || path.Contains("sendotpasync")
                 || path.Contains("DomainWiseClientDetails")

                ))
            {
                await _next(context);
                return;
            }

            // =====================================================
            // 3️⃣ Read Authorization header
            // =====================================================
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Authorization token missing");
                return;
            }

            string token = authHeader.Substring("Bearer ".Length).Trim();

            if (!string.IsNullOrEmpty(token))
            {
                // 3️⃣ Extract USERID & MP_SEAT_ID from JWT
                JwtSecurityToken jwtToken;
                try
                {
                    jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
                }
                catch
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Invalid token format");
                    return;
                }

                string? userId = jwtToken.Claims
                .FirstOrDefault(c => c.Type == "USERID")?.Value;

                string? mpSeatId = jwtToken.Claims
                    .FirstOrDefault(c => c.Type == "MP_SEAT_ID")?.Value;

                // Make available to controllers
                context.Items["USERID"] = userId;
                context.Items["MP_SEAT_ID"] = mpSeatId;

                // 4️⃣ Validate token against DB
                using var scope = _scopeFactory.CreateScope();
                var _core = scope.ServiceProvider.GetRequiredService<IsssCore>();

                var pMessage = new SqlParameter("@pMessage", SqlDbType.NVarChar, 500)
                {
                    Direction = ParameterDirection.Output
                };

                var pStatusCode = new SqlParameter("@pStatusCode", SqlDbType.Int)
                {
                    Direction = ParameterDirection.Output
                };

                SqlParameter[] sqlParams =
                {
                    new SqlParameter("@pTOKEN", token),
                    new SqlParameter("@pFLAG", "VALIDATE_TOKEN"),
                    new SqlParameter("@pUSERID", userId),
                    new SqlParameter("@pMP_SEAT_ID", mpSeatId),
                    pMessage,
                    pStatusCode
                };

                DataTable dt = _core.ExecProcDt("ReactCrudPortalLoginHistoryDetails", sqlParams);

                bool isValid = dt.Rows.Count > 0 && Convert.ToBoolean(dt.Rows[0]["IS_ACTIVE"]);
                int statusCode = (pStatusCode.Value != DBNull.Value) ? Convert.ToInt32(pStatusCode.Value) : 0;
                string message = pMessage.Value?.ToString() ?? "";

                if (!isValid || statusCode != 200)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync(
                        string.IsNullOrEmpty(message)
                        ? "Session expired or logged out from another device."
                        : message
                    );
                    return;
                }
            }

            await _next(context);
        }
        catch (Exception ex)
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("Token validation failed: " + ex.Message);
        }
    }
}