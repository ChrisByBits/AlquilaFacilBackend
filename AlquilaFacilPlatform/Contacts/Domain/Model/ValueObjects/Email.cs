namespace AlquilaFacilPlatform.Contacts.Domain.Model.ValueObjects;

public record Email(String EmailAdress)
{
    public Email() : this(String.Empty)
    {
        
    }
}