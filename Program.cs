using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using WASM_Weather_Server.Data;
using WASM_Weather_Server.Models;
using Supabase;
using Supabase.Gotrue;
using Supabase.Interfaces;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigins", builder =>
    {
        builder.WithOrigins("http://localhost:5170") // Add your client URL(s) here
               .AllowAnyMethod()
               .AllowAnyHeader()
               .AllowCredentials(); // Allow cookies or credentials
    });
});


builder.Services.AddSingleton(_ =>
{
    var url = builder.Configuration["Supabase:Url"];
    var key = builder.Configuration["Supabase:ApiKey"];

    Console.WriteLine("The api key is" + key);
    Console.WriteLine("the Url is" + url);
    var supaOptions = new SupabaseOptions
    {
        AutoConnectRealtime = true
    };

    var supabaseClient = new Supabase.Client(url, key, supaOptions);
    supabaseClient.InitializeAsync().Wait(); // Ensure async initialization

    // Check Supabase connection
    try
    {   

        var currentUser = supabaseClient.Auth.CurrentUser;
        if (currentUser != null)
        {
            Console.WriteLine($"Supabase connected. Authenticated user: {currentUser.Email}");
        }
        else
        {
            Console.WriteLine("Supabase connected but no authenticated user.");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Failed to connect to Supabase: {ex.Message}");
    }

    return supabaseClient;
});



// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<SqlDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("SQLConnection")));

// Adding Identity for role-based authentication and the required model
builder.Services.AddIdentity<WASM_Weather_Server.Models.User, IdentityRole>()
    .AddEntityFrameworkStores<SqlDbContext>()
    .AddDefaultTokenProviders();

// Configuring Swagger UI
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Your API Title", Version = "v1" });

    // Add security definition for JWT Bearer
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter token in the format **Bearer {token}**",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });

    // Add security requirement
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

// JWT Authentication Configuration
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme; // Default to JWT
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme; // Challenge with JWT by default
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Testing the SQL Connection and Seeding Roles
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var dbContext = services.GetRequiredService<SqlDbContext>();
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

    // Check SQL Server Connection
    if (dbContext.Database.CanConnect())
    {
        Console.WriteLine("Connected to SQL Server!");
    }
    else
    {
        Console.WriteLine("Failed to connect to SQL Server.");
    }

    // Seed Roles
    await SeedRoles(roleManager);
}





app.UseHttpsRedirection();
//app.UseCors("AllowAllOrigins");  // Use correct CORS policy
app.UseCors("AllowSpecificOrigins");

app.UseAuthentication(); // Add this before UseAuthorization
app.UseAuthorization();
app.MapControllers();
app.Run();

static async Task SeedRoles(RoleManager<IdentityRole> roleManager)
{
    try
    {
        if (!await roleManager.RoleExistsAsync("Admin"))
        {
            await roleManager.CreateAsync(new IdentityRole("Admin"));
        }

        if (!await roleManager.RoleExistsAsync("User"))
        {
            await roleManager.CreateAsync(new IdentityRole("User"));
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error seeding roles: {ex.Message}");
    }
}
