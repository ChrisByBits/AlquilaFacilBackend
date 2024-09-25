using AlquilaFacilPlatform.Locals.Domain.Model.Commands;
using AlquilaFacilPlatform.Locals.Domain.Model.Entities;
using AlquilaFacilPlatform.Locals.Domain.Repositories;
using AlquilaFacilPlatform.Locals.Domain.Services;
using AlquilaFacilPlatform.Shared.Domain.Repositories;

namespace AlquilaFacilPlatform.Locals.Application.Internal.CommandServices;

public class LocalCategoryCommandService(ILocalCategoryRepository localCategoryRepository, IUnitOfWork unitOfWork)
:ILocalCategoryCommandService
{
    public async Task<LocalCategory?> Handle(CreateLocalCategoryCommand command)
    {
        var localCategory = new LocalCategory(command.Name);
        await localCategoryRepository.AddAsync(localCategory);
        await unitOfWork.CompleteAsync();
        return localCategory;
    }
}