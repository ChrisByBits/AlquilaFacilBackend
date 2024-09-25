using AlquilaFacilPlatform.Locals.Domain.Model.Entities;
using AlquilaFacilPlatform.Locals.Domain.Repositories;
using AlquilaFacilPlatform.Shared.Infrastructure.Persistence.EFC.Configuration;
using AlquilaFacilPlatform.Shared.Infrastructure.Persistence.EFC.Repositories;

namespace AlquilaFacilPlatform.Locals.Infraestructure.Persistence.EFC.Repositories;

public class LocalCategoryRepository(AppDbContext context)
    : BaseRepository<LocalCategory>(context), ILocalCategoryRepository;
