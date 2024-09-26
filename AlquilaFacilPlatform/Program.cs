using AlquilaFacilPlatform.Contacts.Application.Internal.CommandServices;
using AlquilaFacilPlatform.Contacts.Application.Internal.OutboundServices;
using AlquilaFacilPlatform.Contacts.Application.Internal.QueryService;
using AlquilaFacilPlatform.Contacts.Domain.Repositories;
using AlquilaFacilPlatform.Contacts.Domain.Services;
using AlquilaFacilPlatform.Contacts.Infrastructure.Persistence.EFC.Repositories;
using AlquilaFacilPlatform.IAM.Application.Internal.CommandServices;
using AlquilaFacilPlatform.IAM.Application.Internal.OutboundServices;
using AlquilaFacilPlatform.IAM.Application.Internal.QueryServices;
using AlquilaFacilPlatform.IAM.Domain.Model.Commands;
using AlquilaFacilPlatform.IAM.Domain.Respositories;
using AlquilaFacilPlatform.IAM.Domain.Services;
using AlquilaFacilPlatform.IAM.Infrastructure.Hashing.BCrypt.Services;
using AlquilaFacilPlatform.IAM.Infrastructure.Persistence.EFC.Respositories;
using AlquilaFacilPlatform.IAM.Infrastructure.Pipeline.Middleware.Extensions;
using AlquilaFacilPlatform.IAM.Infrastructure.Tokens.JWT.Configuration;
using AlquilaFacilPlatform.IAM.Infrastructure.Tokens.JWT.Services;
using AlquilaFacilPlatform.IAM.Interfaces.ACL;
using AlquilaFacilPlatform.IAM.Interfaces.ACL.Service;
using AlquilaFacilPlatform.Locals.Application.Internal.CommandServices;
using AlquilaFacilPlatform.Locals.Application.Internal.QueryServices;
using AlquilaFacilPlatform.Locals.Domain.Repositories;
using AlquilaFacilPlatform.Locals.Domain.Services;
using AlquilaFacilPlatform.Locals.Infraestructure.Persistence.EFC.Repositories;
using AlquilaFacilPlatform.Locals.Interfaces.ACL;
using AlquilaFacilPlatform.Locals.Interfaces.ACL.Services;
using AlquilaFacilPlatform.Profiles.Application.Internal.CommandServices;
using AlquilaFacilPlatform.Profiles.Application.Internal.OutboundServices;
using AlquilaFacilPlatform.Profiles.Application.Internal.QueryServices;
using AlquilaFacilPlatform.Profiles.Domain.Repositories;
using AlquilaFacilPlatform.Profiles.Domain.Services;
using AlquilaFacilPlatform.Profiles.Infrastructure.Persistence.EFC.Repositories;
using AlquilaFacilPlatform.Profiles.Interfaces.ACL;
using AlquilaFacilPlatform.Profiles.Interfaces.ACL.Services;
using AlquilaFacilPlatform.Shared.Domain.Repositories;
using AlquilaFacilPlatform.Shared.Infrastructure.Interfaces.ASP.Configuration;
using AlquilaFacilPlatform.Shared.Infrastructure.Persistence.EFC.Configuration;
using AlquilaFacilPlatform.Shared.Infrastructure.Persistence.EFC.Repositories;
using AlquilaFacilPlatform.Subscriptions.Application.Internal.CommandServices;
using AlquilaFacilPlatform.Subscriptions.Application.Internal.OutBoundServices;
using AlquilaFacilPlatform.Subscriptions.Application.Internal.QueryServices;
using AlquilaFacilPlatform.Subscriptions.Domain.Model.Commands;
using AlquilaFacilPlatform.Subscriptions.Domain.Repositories;
using AlquilaFacilPlatform.Subscriptions.Domain.Services;
using AlquilaFacilPlatform.Subscriptions.Infrastructure.Persistence.EFC.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers( options => options.Conventions.Add(new KebabCaseRouteNamingConvention()));

// Add Database Connection
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

// Configure Database Context and Logging Levels

builder.Services.AddDbContext<AppDbContext>(
    options =>
    {
        if (connectionString != null)
            if (builder.Environment.IsDevelopment())
                options.UseMySQL(connectionString)
                    .LogTo(Console.WriteLine, LogLevel.Information)
                    .EnableSensitiveDataLogging()
                    .EnableDetailedErrors();
            else if (builder.Environment.IsProduction())
                options.UseMySQL(connectionString)
                    .LogTo(Console.WriteLine, LogLevel.Error)
                    .EnableDetailedErrors();    
    });
// Configure Lowercase URLs
builder.Services.AddRouting(options => options.LowercaseUrls = true);

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(
    c =>
    {
        c.SwaggerDoc("v1",
            new OpenApiInfo
            {
                Title = "AlquilaFacil.API",
                Version = "v1",
                Description = "Alquila Facil API",
                TermsOfService = new Uri("https://alquila-facil.com/tos"),
                Contact = new OpenApiContact
                {
                    Name = "Alquila Facil",
                    Email = "contact@alquilaf.com"
                },
                License = new OpenApiLicense
                {
                    Name = "Apache 2.0",
                    Url = new Uri("https://www.apache.org/licenses/LICENSE-2.0.html")
                }
            });
        c.EnableAnnotations();
        c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
        {
            In = ParameterLocation.Header,
            Description = "Please enter token",
            Name = "Authorization",
            Type = SecuritySchemeType.Http,
            BearerFormat = "JWT",
            Scheme = "bearer"
        });
        c.AddSecurityRequirement(new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Id = "Bearer",
                        Type = ReferenceType.SecurityScheme
                    }
                },
                Array.Empty<string>()
            }
        });
    });

builder.Services.AddRouting(options => options.LowercaseUrls = true);

// Add CORS Policy
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllPolicy",
        policy => policy.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader());
});


builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();

builder.Services.AddScoped<ISubscriptionRepository, SubscriptionRepository>();
builder.Services.AddScoped<ISubscriptionCommandService, SubscriptionCommandService>();
builder.Services.AddScoped<ISubscriptionQueryServices, SubscriptionQueryService>();
builder.Services.AddScoped<IExternalUserWithSubscriptionService, ExternalUserWithSubscriptionService>();

builder.Services.AddScoped<IPlanRepository, PlanRepository>();
builder.Services.AddScoped<IPlanCommandService, PlanCommandService>();
builder.Services.AddScoped<IPlanQueryService, PlanQueryService>();

builder.Services.AddScoped<IInvoiceQueryService, InvoiceQueryService>();
builder.Services.AddScoped<IInvoiceRepository, InvoiceRepository>();
builder.Services.AddScoped<IInvoiceCommandService, InvoiceCommandService>();

        

// Shared Bounded Context Injection Configuration
builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();

// Profiles Bounded Context Injection Configuration
builder.Services.AddScoped<ILocalCommandService, LocalCommandService>();
builder.Services.AddScoped<ILocalQueryService, LocalQueryService>();
builder.Services.AddScoped<ILocalsContextFacade, LocalsContextFacade>();
builder.Services.AddScoped<ILocalRepository, LocalRepository>();
builder.Services.AddScoped<ILocalCategoryRepository, LocalCategoryRepository>();
builder.Services.AddScoped<ILocalCategoryCommandService, LocalCategoryCommandService>();
builder.Services.AddScoped<ILocalCategoryQueryService, LocalCategoryQueryService>();

// Contact Bounded Context Injection Configuration

builder.Services.AddScoped<IContactRepository, ContactRepository>();
builder.Services.AddScoped<IContactCommandService, ContactCommandService>();
builder.Services.AddScoped<IContactQueryService, ContactQueryService>();
builder.Services.AddScoped<IExternalUserService, ExternalUserService>();


builder.Services.AddScoped<ISubscriptionStatusRepository, SubscriptionStatusRepository>();
builder.Services.AddScoped<ISubscriptionStatusCommandService, SubscriptionStatusCommandService>();


// Profiles Bounded Context Injection Configuration
builder.Services.AddScoped<IProfileRepository, ProfileRepository>();
builder.Services.AddScoped<IProfileCommandService, ProfileCommandService>();
builder.Services.AddScoped<IProfileQueryService, ProfileQueryService>();
builder.Services.AddScoped<IProfilesContextFacade, ProfilesContextFacade>();
builder.Services.AddScoped<IUserExternalService, UserExternalService>();


builder.Services.AddScoped<IUserRoleRepository, UserRoleRepository>();
builder.Services.AddScoped<ISeedUserRoleCommandService, SeedUserRoleCommandService>();

// IAM Bounded Context Injection Configuration
builder.Services.Configure<TokenSettings>(builder.Configuration.GetSection("TokenSettings"));

builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IUserCommandService, UserCommandService>();
builder.Services.AddScoped<IUserQueryService, UserQueryService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IHashingService, HashingService>();
builder.Services.AddScoped<IIamContextFacade, IamContextFacade>();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<AppDbContext>();
    context.Database.EnsureCreated();
    
    var subscriptionStatusCommandService = services.GetRequiredService<ISubscriptionStatusCommandService>();
    await subscriptionStatusCommandService.Handle(new SeedSubscriptionStatusCommand());
    
    var userRoleCommandService = services.GetRequiredService<ISeedUserRoleCommandService>();
    await userRoleCommandService.Handle(new SeedUserRolesCommand());
}



// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseSwagger();
app.UseSwaggerUI();

app.UseCors("AllowAllPolicy");

app.UseRequestAuthorization();

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
