using AlquilaFacilPlatform.IAM.Application.Internal.OutboundServices;
using AlquilaFacilPlatform.IAM.Domain.Model.Queries;
using AlquilaFacilPlatform.IAM.Domain.Services;
using AlquilaFacilPlatform.IAM.Infrastructure.Pipeline.Middleware.Attributes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AlquilaFacilPlatform.IAM.Infrastructure.Pipeline.Middleware.Components;

public class RequestAuthorizationMiddleware(RequestDelegate next)
{
    /**
     * InvokeAsync is called by the ASP.NET Core runtime.
     * It is used to authorize requests.
     * It validates a token is included in the request header and that the token is valid.
     * If the token is valid then it sets the user in HttpContext.Items["User"].
     */
    public async Task InvokeAsync(
    HttpContext context,
    IUserQueryService userQueryService,
    ITokenService tokenService)
{
    Console.WriteLine("Entering InvokeAsync");

    var endpoint = context.Request.HttpContext.GetEndpoint();
    if (endpoint == null) throw new InvalidOperationException("Endpoint not found.");

    var allowAnonymous = endpoint.Metadata
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
    if (userId == null) throw new UnauthorizedAccessException("Invalid token");

    var getUserByIdQuery = new GetUserByIdQuery(userId.Value);
    var user = await userQueryService.Handle(getUserByIdQuery);

    if (user == null) throw new KeyNotFoundException("User not found");

    Console.WriteLine("Successful authorization. Updating Context...");
    context.Items["User"] = user;
    Console.WriteLine("Continuing with Middleware Pipeline");
    await next(context);
}
}
