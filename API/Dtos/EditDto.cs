using System.ComponentModel.DataAnnotations;

namespace API.Dtos
{
    public class EditDto
    {
        [EmailAddress]
        public string? Email { get; set; }
        public string? FullName { get; set; }
        public string? Document { get; set; }
        public string[]? Roles { get; set; }
        public string? Password { get; set; }
        public bool? Disabled { get; set; }
    }
}