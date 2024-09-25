using AlquilaFacilPlatform.Locals.Domain.Model.Entities;
using AlquilaFacilPlatform.Locals.Domain.Model.Queries;

namespace AlquilaFacilPlatform.Locals.Domain.Services;

public interface ILocalCategoryQueryService
{
    Task<LocalCategory?> Handle(GetLocalCategoryByIdQuery query);

    Task<IEnumerable<LocalCategory>> Handle(GetAllLocalCategoriesQuery query);
}