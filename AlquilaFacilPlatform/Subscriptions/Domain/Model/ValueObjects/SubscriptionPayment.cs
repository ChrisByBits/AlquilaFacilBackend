namespace AlquilaFacilPlatform.Subscriptions.Domain.Model.ValueObjects;

public class SubscriptionPayment
{
    public int Id { get; }
    public string Type { get; private set; }
    public string Details { get; private set; }

    public SubscriptionPayment(int id, string type, string details)
    {
        Id = id;
        Type = type;
        Details = details;
    }

}