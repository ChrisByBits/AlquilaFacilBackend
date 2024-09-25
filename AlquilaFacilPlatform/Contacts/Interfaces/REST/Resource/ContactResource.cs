using AlquilaFacilPlatform.Contacts.Domain.Model.ValueObjects;

namespace AlquilaFacilPlatform.Contacts.Interfaces.REST.Resource;

public record ContactResource(int Id, string Email, string Message, string NameSurname, string Phone, int UserId);