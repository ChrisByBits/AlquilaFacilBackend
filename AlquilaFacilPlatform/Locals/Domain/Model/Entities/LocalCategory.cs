using AlquilaFacilPlatform.Locals.Domain.Model.Aggregates;

namespace AlquilaFacilPlatform.Locals.Domain.Model.Entities;

public class LocalCategory
{
    public LocalCategory()
    {
        Name = string.Empty;
    }

    public LocalCategory(string name)
    {
        Name = name;
    }

    public int Id { get; set; }
    public string Name { get; set; }
    
}