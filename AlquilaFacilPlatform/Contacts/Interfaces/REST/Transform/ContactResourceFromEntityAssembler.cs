using AlquilaFacilPlatform.Contacts.Domain.Model.Aggregates;
using AlquilaFacilPlatform.Contacts.Interfaces.REST.Resource;

namespace AlquilaFacilPlatform.Contacts.Interfaces.REST.Transform;

public static class ContactResourceFromEntityAssembler
{
    public static ContactResource ToResourceFromEntity(Contact contact)
    {
        return new ContactResource(
            contact.Id,
            contact.Email,
            contact.Message,
            contact.NameSurname,
            contact.Phone,
            contact.UserId);
    }
}