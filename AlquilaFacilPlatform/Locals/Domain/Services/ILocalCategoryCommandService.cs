using AlquilaFacilPlatform.Locals.Domain.Model.Commands;
using AlquilaFacilPlatform.Locals.Domain.Model.Entities;

namespace AlquilaFacilPlatform.Locals.Domain.Services;

public interface ILocalCategoryCommandService
{
    public Task<LocalCategory?> Handle(CreateLocalCategoryCommand command);
}