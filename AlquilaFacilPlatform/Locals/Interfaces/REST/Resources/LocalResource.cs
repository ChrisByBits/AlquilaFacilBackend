namespace AlquilaFacilPlatform.Locals.Interfaces.REST.Resources;

public record LocalResource(int Id, string StreetAddress, string LocalType, string CityPlace, int NightPrice, 
    string PhotoUrl, string DescriptionMessage, int LocalCategoryId, int UserId);