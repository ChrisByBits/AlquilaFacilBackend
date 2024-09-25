using System.Diagnostics;
using AlquilaFacilPlatform.Locals.Domain.Model.Entities;
using AlquilaFacilPlatform.Locals.Interfaces.REST.Resources;

namespace AlquilaFacilPlatform.Locals.Interfaces.REST.Transform;

public static class LocalCategoryResourceFromEntityAssembler
{
    public static LocalCategoryResource ToResourceFromEntity(LocalCategory? entity)
    {
        Console.WriteLine("Local Category Name is " + entity?.Name);
        Debug.Assert(entity != null, nameof(entity) + " != null");
        return new LocalCategoryResource(entity.Id, entity.Name);
    }
}