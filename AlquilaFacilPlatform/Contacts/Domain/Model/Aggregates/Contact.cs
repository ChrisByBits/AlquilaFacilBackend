using System.Collections;
using AlquilaFacilPlatform.Contacts.Domain.Model.Commands;
using AlquilaFacilPlatform.Contacts.Domain.Model.ValueObjects;
using Phone = AlquilaFacilPlatform.Profiles.Domain.Model.ValueObjects.Phone;

namespace AlquilaFacilPlatform.Contacts.Domain.Model.Aggregates;

public partial class Contact 
{
    public Contact()
    {
        EAdress = new Email();
        CMessage = new Message();
        FullName = new NameSurname();
        NPhone = new Phone();
        UserId = 0;
    }

    public Contact(string name, string lastname, string message, string email, string phone, int userId) : this()
    {
        EAdress = new Email(email);
        CMessage = new Message(message);
        FullName = new NameSurname(name, lastname);
        NPhone = new Phone(phone);
        UserId = userId;
    }

    public Contact(CreateContactCommand command)
    {
        EAdress = new Email(command.Email);
        CMessage = new Message(command.Message);
        FullName = new NameSurname(command.Name, command.Lastname);
        NPhone = new Phone(command.Phone);
        UserId = command.UserId;
    }

    public int Id { get; }

    public Email EAdress { get; private set; }
    public Message CMessage { get; private set; }
    public NameSurname FullName { get; private set; }
    public Phone NPhone { get; private set; }
    
    public int UserId { get; set; }
    public string Email => EAdress.EmailAdress;
    public string Message => CMessage.ContactMessage;
    public string NameSurname => FullName.FullSurname;
    public string Phone => NPhone.PhoneNumber;
    
}