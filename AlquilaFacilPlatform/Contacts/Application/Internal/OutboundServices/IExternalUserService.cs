namespace AlquilaFacilPlatform.Contacts.Application.Internal.OutboundServices;

public interface IExternalUserService
{
    bool UserExists(int userId);
}