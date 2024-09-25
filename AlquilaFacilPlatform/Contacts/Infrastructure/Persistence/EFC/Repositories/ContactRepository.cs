using AlquilaFacilPlatform.Contacts.Domain.Model.Aggregates;
using AlquilaFacilPlatform.Contacts.Domain.Repositories;
using AlquilaFacilPlatform.Shared.Infrastructure.Persistence.EFC.Configuration;
using AlquilaFacilPlatform.Shared.Infrastructure.Persistence.EFC.Repositories;
using Microsoft.EntityFrameworkCore;

namespace AlquilaFacilPlatform.Contacts.Infrastructure.Persistence.EFC.Repositories;

public class ContactRepository(AppDbContext context) : BaseRepository<Contact>(context), IContactRepository
{
    
    public async Task<IEnumerable<Contact>> FindContactsByUserIdAsync(int userId)
    {
        return await Context.Set<Contact>().Where(c => c.UserId == userId).ToListAsync();
    }
}