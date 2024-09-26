using AlquilaFacilPlatform.IAM.Application.Internal.OutboundServices;
using AlquilaFacilPlatform.IAM.Domain.Model.Queries;
using AlquilaFacilPlatform.IAM.Domain.Services;
using AlquilaFacilPlatform.IAM.Infrastructure.Pipeline.Middleware.Attributes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AlquilaFacilPlatform.IAM.Infrastructure.Pipeline.Middleware.Components;

public class RequestAuthorizationMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(
        HttpContext context,
        IUserQueryService userQueryService,
        ITokenService tokenService)
    {
        Console.WriteLine("Entering InvokeAsync");
        var endpoint = context.Request.HttpContext.GetEndpoint();
        if (endpoint == null)
        {
            // Manejar el caso donde el endpoint es nulo
            throw new InvalidOperationException("Endpoint not found");
        }
        var allowAnonymous = context.Request.HttpContext.GetEndpoint()!.Metadata
            .Any(m => m.GetType() == typeof(AllowAnonymousAttribute));
        Console.WriteLine($"Allow Anonymous is {allowAnonymous}");
        if (allowAnonymous)
        {
            Console.WriteLine("Skipping authorization");
            await next(context);
            return;
        }
        Console.WriteLine("Entering authorization");
        var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

        if (token == null) throw new Exception("Null or invalid token");

        var userId = await tokenService.ValidateToken(token);

        if (userId == null) throw new Exception("Invalid token");

        var getUserByIdQuery = new GetUserByUserIdQuery(userId.Value);

        var user = await userQueryService.Handle(getUserByIdQuery);
        Console.WriteLine("Successful authorization. Updating Context...");
        context.Items["User"] = user;
        Console.WriteLine("Continuing with Middleware pipeline...");
        await next(context);
    }
}
