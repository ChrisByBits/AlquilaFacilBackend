namespace AlquilaFacilPlatform.Contacts.Domain.Model.ValueObjects;

public record NameSurname(string Name, string Lastname)
{
    public NameSurname() : this(string.Empty, string.Empty)
    {
    }

    public NameSurname(string name) : this(name, string.Empty)
    {
    }

    public string FullSurname => $"{Name} {Lastname}";
}