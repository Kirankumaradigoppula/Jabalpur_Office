using System.ComponentModel.DataAnnotations;

namespace Jabalpur_Office.Models
{
    public class LoginSeatRequest
    {
        [Required(ErrorMessage = "Name is required.")]
        public string NAME { get;set;}

        [Required(ErrorMessage = "Mobile number is required.")]
        public string MOBNO { get; set; }
    }
}
