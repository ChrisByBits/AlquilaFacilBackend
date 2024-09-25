namespace AlquilaFacilPlatform.IAM.Interfaces.ACL;

public interface IIamContextFacade
{
    Task<int> CreateUser(string username, string password, string name, string fatherName, string motherName, string dateOfBirth, string documentNumber,
        string phone, string email);
    Task<int> FetchUserIdByUsername(string username);
    Task<string> FetchUsernameByUserId(int userId);
    
   bool UsersExists(int userId);
}