using AlquilaFacilPlatform.IAM.Domain.Model.Aggregates;
using AlquilaFacilPlatform.Profiles.Domain.Model.Commands;
using AlquilaFacilPlatform.Profiles.Domain.Model.ValueObjects;

namespace AlquilaFacilPlatform.Profiles.Domain.Model.Aggregates;

public partial class Profile
{
    public Profile()
    {
        Name = new PersonName();
        Birth = new DateOfBirth();
        PhoneN = new Phone();
        DocumentN = new DocumentNumber();
        UserId = 0;
    }

    public Profile(string name, string? fatherName, string? motherName, string dateOfBirth, string documentNumber,
        string phone,int userId) : this()
    {
        Name = new PersonName(name, fatherName, motherName);
        Birth = new DateOfBirth(dateOfBirth);
        PhoneN = new Phone(phone);
        DocumentN = new DocumentNumber(documentNumber);
        UserId = userId;
    }
    
    public Profile(CreateProfileCommand command)
    {
        Name = new PersonName(command.Name, command.FatherName, command.MotherName);
        Birth = new DateOfBirth(command.DateOfBirth);
        PhoneN = new Phone(command.Phone);
        DocumentN = new DocumentNumber(command.DocumentNumber);
        UserId = command.UserId;
    }
    
    public void Update(UpdateProfileCommand command)
    {
        Name = new PersonName(command.Name, command.FatherName, command.MotherName);
        Birth = new DateOfBirth(command.DateOfBirth);
        PhoneN = new Phone(command.Phone);
        DocumentN = new DocumentNumber(command.DocumentNumber);
    }

    public int Id { get; }
    public PersonName Name { get; private set; }
    public DateOfBirth Birth { get; private set; }
    public Phone PhoneN { get; private set; }
    public DocumentNumber DocumentN { get; private set; }
    

    //public User User { get; internal set; }
    //public int UserId { get; internal set; }
    
    public int UserId { get; set; }

    public string FullName => Name.FullName;
    public string BirthDate => Birth.BirthDate;
    public string PhoneNumber => PhoneN.PhoneNumber;
    public string NumberDocument => DocumentN.NumberDocument;
    
}