using System.Net.Mime;
using AlquilaFacilPlatform.Locals.Domain.Model.Queries;
using AlquilaFacilPlatform.Locals.Domain.Services;
using AlquilaFacilPlatform.Locals.Interfaces.REST.Resources;
using AlquilaFacilPlatform.Locals.Interfaces.REST.Transform;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace AlquilaFacilPlatform.Locals.Interfaces.REST;


[ApiController]
[Route("api/v1/[controller]")]
[Produces(MediaTypeNames.Application.Json)]
public class LocalCategoriesController(
    ILocalCategoryCommandService localCategoryCommandService,
    ILocalCategoryQueryService localCategoryQueryService) : ControllerBase
{

    [HttpPost]
    [SwaggerOperation(
        Summary = "Creates a local category",
        Description = "Creates a local category with a given name",
        OperationId = "CreateLocalCategory")]
    [SwaggerResponse(201, "The local category was created", typeof(LocalCategoryResource))]
    public async Task<IActionResult> CreateLocalCategory(
        [FromBody] CreateLocalCategoryResource createLocalCategoryResource)
    {
        var createLocalCategoryCommand =
            CreateLocalCategoryCommandFromResourceAssembler.ToCommandFromResource(createLocalCategoryResource);
        var localCategory = await localCategoryCommandService.Handle(createLocalCategoryCommand);
        if (localCategory is null) return BadRequest();
        var resource = LocalCategoryResourceFromEntityAssembler.ToResourceFromEntity(localCategory);
        return CreatedAtAction(nameof(GetLocalCategoryById), new { localCategoryId = resource.Id }, resource);
    }
    
    [HttpGet("{localCategoryId:int}")]
    [SwaggerOperation(
        Summary = "Gets a local category by id",
        Description = "Gets a local category for a given identifier",
        OperationId = "GetLocalCategoryById")]
    [SwaggerResponse(200, "The category was found", typeof(LocalCategoryResource))]
    public async Task<IActionResult> GetLocalCategoryById(int localCategoryId)
    {
        var getLocalCategoryByIdQuery = new GetLocalCategoryByIdQuery(localCategoryId);
        var localCategory = await localCategoryQueryService.Handle(getLocalCategoryByIdQuery);
        var resource = LocalCategoryResourceFromEntityAssembler.ToResourceFromEntity(localCategory);
        return Ok(resource);
    }


    [HttpGet]
    [SwaggerOperation(
        Summary = "Gets all local categories",
        Description = "Gets all local categories",
        OperationId = "GetAllLocalCategories")]
    [SwaggerResponse(200, "The categories were found", typeof(IEnumerable<LocalCategoryResource>))]
    public async Task<IActionResult> GetAllLocalCategories()
    {
        var getAllLocalCategoriesQuery = new GetAllLocalCategoriesQuery();
        var localcategories = await localCategoryQueryService.Handle(getAllLocalCategoriesQuery);
        var resources = localcategories.
            Select(LocalCategoryResourceFromEntityAssembler.ToResourceFromEntity);
        return Ok(resources);
    }
    
}