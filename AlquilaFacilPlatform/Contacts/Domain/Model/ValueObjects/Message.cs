namespace AlquilaFacilPlatform.Contacts.Domain.Model.ValueObjects;

public record Message(string ContactMessage)
{
    public Message() : this(String.Empty)
    {
        
    }
}