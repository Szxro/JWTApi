using JWTApi.Services.SecurityServices;
using JWTApi.Services.UserServices;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddScoped<ISecurityServices, SecurityService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddControllers();
//Accesing to the user claims
builder.Services.AddHttpContextAccessor();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    //Adding the Authentication Header
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        //Adding some descriptions and other stufss
        Description ="Standard Authorization header using the Bearer Scheme(\"bearer {token}\")" ,
        In= ParameterLocation.Header,
        Name="Authorization",
        Type = SecuritySchemeType.ApiKey
    });
    //Lastly adding the operation filter
    options.OperationFilter<SecurityRequirementsOperationFilter>();
});
// Adding the Authentication 
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        //Adding the TokenValidation Parameters
    options.TokenValidationParameters = new TokenValidationParameters
    {
        //Parameters
        ValidateIssuerSigningKey = true,
        //Giving the security key
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8
            .GetBytes(builder.Configuration.GetSection("AppSettings:Token").Value)),
        ValidateIssuer = false,
        ValidateAudience = false,
        };
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
