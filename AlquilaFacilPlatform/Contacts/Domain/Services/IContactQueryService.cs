using AlquilaFacilPlatform.Contacts.Domain.Model.Aggregates;
using AlquilaFacilPlatform.Contacts.Domain.Model.Queries;

namespace AlquilaFacilPlatform.Contacts.Domain.Services;

public interface IContactQueryService
{
    Task<IEnumerable<Contact>> Handle(GetAllContactQuery query);
    Task<IEnumerable<Contact>> Handle(GetContactsByUserIdQuery query);
    Task<Contact?> Handle(GetContactByIdQuery query);

}