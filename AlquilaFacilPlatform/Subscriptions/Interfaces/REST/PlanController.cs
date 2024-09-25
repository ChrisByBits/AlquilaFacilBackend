using AlquilaFacilPlatform.Subscriptions.Domain.Model.Queries;
using AlquilaFacilPlatform.Subscriptions.Domain.Services;
using AlquilaFacilPlatform.Subscriptions.Interfaces.REST.Resources;
using AlquilaFacilPlatform.Subscriptions.Interfaces.REST.Transform;
using Microsoft.AspNetCore.Mvc;

namespace AlquilaFacilPlatform.Subscriptions.Interfaces.REST;

[ApiController]
[Route("api/v1/[controller]")]
public class PlanController(IPlanCommandService planCommandService, IPlanQueryService planQueryService) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> CreatePlan([FromBody] CreatePlanResource createPlanResource)
    {
        var createPlanCommand = CreatePlanCommandFromResourceAssembler.ToCommandFromResource(createPlanResource);
        var plan = await planCommandService.Handle(createPlanCommand);
        if (plan == null) return NotFound();
        var resource = PlanResourceFromEntityAssembler.ToResourceFromEntity(plan);
        return StatusCode(201, resource);
    }
    
    [HttpGet("{planId:int}")]
    public async Task<IActionResult> GetPlanById(int planId)
    {
        var getPlanByIdQuery = new GetPlanByIdQuery(planId);
        var plan = await planQueryService.Handle(getPlanByIdQuery);
        if (plan == null) return NotFound();
        var resource = PlanResourceFromEntityAssembler.ToResourceFromEntity(plan);
        return Ok(resource);
    }
    
    [HttpGet]
    public async Task<IActionResult> GetAllPlans()
    {
        var getAllPlansQuery = new GetAllPlansQuery();
        var plans = await planQueryService.Handle(getAllPlansQuery);
        var resources = plans.Select(PlanResourceFromEntityAssembler.ToResourceFromEntity);
        return Ok(resources);
    }

}