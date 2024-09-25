using AlquilaFacilPlatform.Contacts.Domain.Model.Aggregates;
using AlquilaFacilPlatform.Contacts.Domain.Model.Commands;

namespace AlquilaFacilPlatform.Contacts.Domain.Services;

public interface IContactCommandService
{
    Task<Contact?> Handle(CreateContactCommand command);
}