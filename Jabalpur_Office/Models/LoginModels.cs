using System.ComponentModel.DataAnnotations;

namespace Jabalpur_Office.Models
{
    public class LoginSeatRequest
    {
        [Required(ErrorMessage = "Name is required.")]
        public string NAME { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mobile number is required.")]
        public string MOBNO { get; set; } = string.Empty;
    }

    public class ValidateUserRequest
    {
        [Required(ErrorMessage = "MP Seat is required.")]
        public string MP_SEAT_ID { get; set; } = string.Empty;

        [Required(ErrorMessage = "Username is required.")]
        public string USERNAME { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password number is required.")]
        public string PASSWORD { get; set; } = string.Empty;
    }

    public class OtpRequest
    {
        [Required(ErrorMessage = "Mobile Number is required")]
        public string MOBNO { get; set; } = string.Empty;


        [Required(ErrorMessage = "Role Number is required")]
        public string ROLE { get; set; } = string.Empty;
    }
}
