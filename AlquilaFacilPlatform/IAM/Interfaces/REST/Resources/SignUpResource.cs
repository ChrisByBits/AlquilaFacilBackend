namespace AlquilaFacilPlatform.IAM.Interfaces.REST.Resources;

public record SignUpResource(string Username, string Password, string Name, string FatherName, string MotherName, string DateOfBirth, string DocumentNumber,
    string Phone, string Email );