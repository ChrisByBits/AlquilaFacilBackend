using AlquilaFacilPlatform.IAM.Domain.Model.Aggregates;
using AlquilaFacilPlatform.Profiles.Domain.Model.Aggregates;
using AlquilaFacilPlatform.Profiles.Domain.Repositories;
using AlquilaFacilPlatform.Shared.Infrastructure.Persistence.EFC.Configuration;
using AlquilaFacilPlatform.Shared.Infrastructure.Persistence.EFC.Repositories;
using Microsoft.EntityFrameworkCore;

namespace AlquilaFacilPlatform.Profiles.Infrastructure.Persistence.EFC.Repositories;


public class ProfileRepository(AppDbContext context) : BaseRepository<Profile>(context), IProfileRepository
{
    
    public async Task<List<Profile>> GetProfilesByDocumentNumber(string commandDocumentNumber)
    {
        return await Context.Set<Profile>()
            .Where(p => p.DocumentN.NumberDocument == commandDocumentNumber)
            .ToListAsync();
    }
    
    
}