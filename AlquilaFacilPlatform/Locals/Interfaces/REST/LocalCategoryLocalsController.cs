using System.Net.Mime;
using AlquilaFacilPlatform.Locals.Domain.Model.Queries;
using AlquilaFacilPlatform.Locals.Domain.Services;
using AlquilaFacilPlatform.Locals.Interfaces.REST.Transform;
using Microsoft.AspNetCore.Mvc;

namespace AlquilaFacilPlatform.Locals.Interfaces.REST;


[ApiController]
[Route("/api/v1/categories/{localCategoryId}/locals")]
[Produces(MediaTypeNames.Application.Json)]
[Tags("LocalCategories")]
public class LocalCategoryLocalsController(ILocalQueryService localQueryService) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetLocalsByLocalCategoryId([FromRoute] int localCategoryId)
    {
        var getAllLocalsByLocalCategoryIdQuery = new GetAllLocalsByLocalCategoryIdQuery(localCategoryId);
        var locals = await localQueryService.Handle(getAllLocalsByLocalCategoryIdQuery);
        var resources = locals.Select(LocalResourceFromEntityAssembler.ToResourceFromEntity);
        return Ok(resources);
    }
}