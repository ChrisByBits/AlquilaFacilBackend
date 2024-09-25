using AlquilaFacilPlatform.Contacts.Domain.Model.Aggregates;
using AlquilaFacilPlatform.Contacts.Domain.Model.Queries;
using AlquilaFacilPlatform.Contacts.Domain.Repositories;
using AlquilaFacilPlatform.Contacts.Domain.Services;

namespace AlquilaFacilPlatform.Contacts.Application.Internal.QueryService;

public class ContactQueryService(IContactRepository contactRepository) : IContactQueryService
{
    public async Task<IEnumerable<Contact>> Handle(GetAllContactQuery query)
    {
        return await contactRepository.ListAsync();
    }

    public async Task<IEnumerable<Contact>> Handle(GetContactsByUserIdQuery query)
    {
        return await contactRepository.FindContactsByUserIdAsync(query.propertyId);
    }

    public async Task<Contact?> Handle(GetContactByIdQuery query)
    {
        return await contactRepository.FindByIdAsync(query.Id);
    }
}