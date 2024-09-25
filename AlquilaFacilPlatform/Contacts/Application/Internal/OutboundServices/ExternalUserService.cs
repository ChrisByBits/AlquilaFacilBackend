using AlquilaFacilPlatform.IAM.Interfaces.ACL;

namespace AlquilaFacilPlatform.Contacts.Application.Internal.OutboundServices;

public class ExternalUserService(IIamContextFacade iamContextFacade) : IExternalUserService
{
    public bool UserExists(int userId)
    {
        return iamContextFacade.UsersExists(userId);
    }
}