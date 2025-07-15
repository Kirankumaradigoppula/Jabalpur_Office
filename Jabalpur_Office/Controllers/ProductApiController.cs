using System.Data;
using Jabalpur_Office.Data;
using Jabalpur_Office.Filters;
using Jabalpur_Office.Helpers;
using Jabalpur_Office.Models;
using Jabalpur_Office.ServiceCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using static Jabalpur_Office.Helpers.ApiHelper;
using static Jabalpur_Office.Filters.JwtTokenHelper;

namespace Jabalpur_Office.Controllers
{
    [Authorize]
    [EnableCors("AllowAll")] // ✅ Use named policy defined in Program.cs
    [Route("api/ProductApiController")]

    [ApiController]
    public class ProductApiController : BaseApiController
    {
        private readonly AppDbContext _context;
        private readonly IsssCore _core;

        private readonly JwtTokenHelper _jwtTokenHelper;

        public ProductApiController(AppDbContext context, IsssCore core, JwtTokenHelper jwtToken) : base(context)
        {
            _context = context;
            _core = core;
            _jwtTokenHelper= jwtToken;
        }

        //1.
        [AllowAnonymous]
        [HttpPost("validateUserLoginSeat")] // Cleaner route syntax
        public IActionResult ValidateUserLoginSeat([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                // Step 1: Prepare output wrapper and extract dictionary
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Converts to Dictionary<string, object>

                // Get only business filter keys -Exclude pSearch, pageIndex, pageSize
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters using helper
                var (paramList, pStatus, pMsg, _, _) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    includeTotalCount: false,
                    includeWhere: false
                );

                // Step 3: Execute stored procedure
                DataTable dt = _core.ExecProcDt("GetReactValidateUserLoginSeat", paramList.ToArray());

                // Step 4: Populate output object
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                //outObj.Message = $"DEBUG: ROWCOUNT={dt?.Rows.Count ?? -1}, MSG={pMsg.Value}, STATUS={pStatus.Value}";
                return outObj;

            }, nameof(ValidateUserLoginSeat), out _, skipTokenCheck: true));
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("validateUser")] //2.
        public IActionResult validateUser([FromBody]  object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                // Safe Dictionary<string, object>
                var data = ApiHelper.ToObjectDictionary(rawData);

                // Dynamic keys (safe even if input is null or empty)
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Use your new unified parameter builder
                var (paramList, pStatus, pMsg, _, _) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    includeTotalCount: false,
                    includeWhere: false
                );
                DataTable dt = _core.ExecProcDt("ReactValidateUser", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);

                SetOutput(pStatus, pMsg, outObj);

                if (dt.Rows.Count > 0)
                {
                    var userId = Convert.ToString(dt.Rows[0]["USERID"]);
                    var userName = Convert.ToString(dt.Rows[0]["FIRSTNAME"]);
                    var mpSeatId = Convert.ToString(dt.Rows[0]["MP_SEAT_ID"]);
                    // JWT token (optional)
                    string jwtToken = _jwtTokenHelper.GenerateToken(userId, userName, mpSeatId);
                    
                    foreach (var item in outObj.DataList)
                    {
                        item["LOGIN_JWT_TOKEN"] = jwtToken;
                    }
                }

                return outObj;


            }, nameof(validateUser), out _, skipTokenCheck: true));
        }


    }
}
