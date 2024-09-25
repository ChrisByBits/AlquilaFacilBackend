using AlquilaFacilPlatform.Locals.Domain.Model.Commands;
using AlquilaFacilPlatform.Locals.Domain.Model.Queries;
using AlquilaFacilPlatform.Locals.Domain.Model.ValueObjects;
using AlquilaFacilPlatform.Locals.Domain.Services;

namespace AlquilaFacilPlatform.Locals.Interfaces.ACL.Services;

public class LocalsContextFacade(ILocalCommandService localCommandService) : ILocalsContextFacade
{
    public async Task<int> CreateLocal(string district, string street, string localType, string country, string city, 
                int price, string photoUrl, string descriptionMessage, int localCategoryId, int userId)
    {
        var createLocalCommand = new CreateLocalCommand(district, street, localType, country, city, price, photoUrl, descriptionMessage ,localCategoryId, userId);
        var local = await localCommandService.Handle(createLocalCommand);
        return local?.Id ?? 0;
    }
}