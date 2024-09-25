using System.Net.Mime;
using AlquilaFacilPlatform.Contacts.Domain.Model.Aggregates;
using AlquilaFacilPlatform.Contacts.Domain.Model.Queries;
using AlquilaFacilPlatform.Contacts.Domain.Repositories;
using AlquilaFacilPlatform.Contacts.Domain.Services;
using AlquilaFacilPlatform.Contacts.Interfaces.REST.Resource;
using AlquilaFacilPlatform.Contacts.Interfaces.REST.Transform;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters;

namespace AlquilaFacilPlatform.Contacts.Interfaces.REST;


[ApiController]
[Route("api/v1/[controller]")]
[Produces(MediaTypeNames.Application.Json)]
public class ContactController(IContactCommandService contactCommandService, IContactQueryService contactQueryService) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> CreateContact(CreateContactResource resource)
    {
        var createContactCommand = CreateContactCommandFromResourceAssembler.ToCommandFromResources(resource);
        var contact = await contactCommandService.Handle(createContactCommand);
        if (contact == null) return NotFound();
        var contactResource = ContactResourceFromEntityAssembler.ToResourceFromEntity(contact);
        return StatusCode(201, contactResource);
    }

    [HttpGet]
    public async Task<IActionResult> GetAllContacts()
    {
        var getAllContactQuery = new GetAllContactQuery();
        var contacts = await contactQueryService.Handle(getAllContactQuery);
        var contactResources = contacts.Select(ContactResourceFromEntityAssembler.ToResourceFromEntity);
        return Ok(contactResources);
    }

    [HttpGet("{contactId}")]
    public async Task<IActionResult> GetContactById(int contactId)
    {
        var getContactByIdQuery = new GetContactByIdQuery(contactId);
        var contact = await contactQueryService.Handle(getContactByIdQuery);
        if (contact == null) return NotFound();
        var contactResource = ContactResourceFromEntityAssembler.ToResourceFromEntity(contact);
        return Ok(contactResource);
    }
    
    [HttpGet("/find-by-userId/{userId}")]
    public  async Task<IActionResult> GetContactsByPropertyId(int userId)
    {
        var getContactsByPropertyIdQuery = new GetContactsByUserIdQuery(userId);
        var contacts =  await contactQueryService.Handle(getContactsByPropertyIdQuery);
        var contactResources = contacts.Select(ContactResourceFromEntityAssembler.ToResourceFromEntity);
        return StatusCode(200, contactResources);
    }
    
    
}