using AlquilaFacilPlatform.Contacts.Domain.Model.Commands;
using AlquilaFacilPlatform.Contacts.Interfaces.REST.Resource;

namespace AlquilaFacilPlatform.Contacts.Interfaces.REST.Transform;

public static class CreateContactCommandFromResourceAssembler
{
    public static CreateContactCommand ToCommandFromResources(CreateContactResource resource)
    {
        return new CreateContactCommand(resource.Name, resource.Lastname, resource.Message, resource.Email,
            resource.Phone, resource.UserId);
    }
}