using AlquilaFacilPlatform.Locals.Domain.Model.Commands;
using AlquilaFacilPlatform.Locals.Interfaces.REST.Resources;

namespace AlquilaFacilPlatform.Locals.Interfaces.REST.Transform;

public class CreateLocalCategoryCommandFromResourceAssembler
{
    public static CreateLocalCategoryCommand ToCommandFromResource(CreateLocalCategoryResource resource)
    {
        return new CreateLocalCategoryCommand(resource.Name);
    }
}