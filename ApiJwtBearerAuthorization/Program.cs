using ApiJwtBearerAuthorization.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var jwtOptions = builder.Configuration
                 .GetSection("JwtOptions")
                 .Get<JwtOptions>();

builder.Services.AddSingleton<JwtOptions>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>
    {
        //convert the string signing key to byte array
        byte[] signingKeyBytes = Encoding.UTF8.GetBytes(jwtOptions.SigningKey);

        opts.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer                  = true,
            ValidateAudience                = true,
            ValidateLifetime                = true,
            ValidateIssuerSigningKey        = true,
            ValidIssuer                     = jwtOptions.Issuer,
            ValidAudience                   = jwtOptions.Audience,
            IssuerSigningKey                = new SymmetricSecurityKey(signingKeyBytes)
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/",        () => "Hello World!");
app.MapGet("/public",  () => "Public Hello World!").AllowAnonymous();
app.MapGet("/private", () => "Private Hello World!").RequireAuthorization();
app.MapGet("/private", () => "Private Hello World!").RequireAuthorization();
app.MapPost("/tokens/connect", (HttpContext ctx, JwtOptions jwtOptions) => TokenEndpoint.Connect(ctx, jwtOptions));

app.MapControllers();

app.Run();
