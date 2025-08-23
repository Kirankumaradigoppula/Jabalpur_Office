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
using static Microsoft.EntityFrameworkCore.DbLoggerCategory;
using Microsoft.Data.SqlClient;
using System.Text;
using System.Net.NetworkInformation;

namespace Jabalpur_Office.Controllers
{
    //[Authorize]
    [EnableCors("AllowAll")] // ✅ Use named policy defined in Program.cs
    [Route("api/ProductApiController")]

    //[ApiController]
    public class ProductApiController : BaseApiController
    {
        private readonly AppDbContext _context;
        private readonly IsssCore _core;

        private readonly JwtTokenHelper _jwtTokenHelper;

        public ProductApiController(AppDbContext context, IsssCore core, JwtTokenHelper jwtToken) : base(context, core, jwtToken)
        {
            _context = context;
            _core = core;
            _jwtTokenHelper = jwtToken;
        }

        //1.
        [AllowAnonymous]
        [HttpPost("validateUserLoginSeat")] // Cleaner route syntax
        public IActionResult ValidateUserLoginSeat([FromBody] LoginSeatRequest input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                // Step 1: Prepare output wrapper and extract dictionary
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input);
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
        public IActionResult validateUser([FromBody] ValidateUserRequest input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input);

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

        [HttpPost]
        [Route("GetOTP")] //3.
        public async Task<IActionResult> GetOTP([FromBody] OtpRequest input)
        {
            return await ExecuteWithHandlingAsync(async () =>
            {
                var (outObj, data) = PrepareWrapperAndData<WrapperObjectData>(input);

                // Get parameters
                var values = ApiHelper.ToObjectDictionary(data);
                string pROLE = values.ContainsKey("ROLE") ? values["ROLE"]?.ToString() ?? "" : "";
                string pMOBNO = values.ContainsKey("MOBNO") ? values["MOBNO"]?.ToString() ?? "" : "";

                // Get OTP_SMS_STATUS from DB
                string pQry = "SELECT DISTINCT OTP_SMS_STATUS FROM MP_SEATS WHERE MP_SEAT_ID = @MP_SEAT_ID";

                string smsOtpStatus = Convert.ToString(
                    await _core.ExecScalarAsync(
                        pQry,
                         new[] { new SqlParameter("@MP_SEAT_ID", pJWT_MP_SEAT_ID) }
                    )
                 );

                Dictionary<string, string> resultData = new();

                if (!string.IsNullOrEmpty(pROLE) && (pROLE.Contains("GUEST") || pROLE.Contains("ADMIN")))
                {
                    if (smsOtpStatus == "Y")
                    {
                        string generatedOtp = new Random().Next(0, 999999).ToString("D6");

                        if (!string.IsNullOrEmpty(generatedOtp) && !string.IsNullOrEmpty(pMOBNO))
                        {
                            string sendResult = await SendOTPAsync(pMOBNO, pJWT_LOGIN_NAME, generatedOtp, "SEND", pROLE, pJWT_MP_SEAT_ID);
                            try
                            {
                                var pMessage = new SqlParameter("@pMessage", SqlDbType.VarChar, 500)
                                {
                                    Direction = ParameterDirection.Output
                                };
                                var pStatusCode = new SqlParameter("@pStatusCode", SqlDbType.Int)
                                {
                                    Direction = ParameterDirection.Output
                                };

                                List<SqlParameter> paramList = new()
                                 {
                                     new SqlParameter("@pROLE", pROLE),
                                     new SqlParameter("@pMOBNO", pMOBNO),
                                     new SqlParameter("@pLoginOTP", generatedOtp),
                                     new SqlParameter("@pMP_SEAT_ID", pJWT_MP_SEAT_ID),
                                     pMessage,
                                     pStatusCode
                                 };
                                await _core.ExecQryAsync("ReactUpdateOTP", paramList.ToArray());

                                resultData["OTP"] = generatedOtp;
                                resultData["Status"] = pStatusCode.Value?.ToString() == "200" ? "SUCCESS" : "FAILED";
                                resultData["Message"] = pMessage.Value?.ToString() ?? "OTP processed.";
                                resultData["StatusCode"] = pStatusCode.Value?.ToString() ?? "200";
                            }
                            catch (Exception Ex)
                            {
                                resultData["Status"] = "FAILED";
                                resultData["Message"] = $"Error saving OTP: {Ex.Message}";
                                resultData["StatusCode"] = "500";
                            }

                        }
                        else
                        {
                            resultData["Status"] = "FAILED";
                            resultData["Message"] = "Missing mobile number or OTP generation failed.";
                            resultData["StatusCode"] = "422";
                        }
                    }
                    else
                    {
                        resultData["Status"] = "FAILED";
                        resultData["Message"] = "OTP sending not enabled.";
                        resultData["StatusCode"] = "403";
                    }
                }
                else
                {
                    resultData["Status"] = "FAILED";
                    resultData["Message"] = "Access denied: Invalid login role.";
                    resultData["StatusCode"] = "403";
                }

                // Set Output
                outObj.DataObject = resultData;
                outObj.StatusCode = int.Parse(resultData["StatusCode"]);
                outObj.Message = resultData["Message"];

                return outObj.StatusCode switch
                {
                    200 => Ok(outObj),
                    403 => Forbid(),
                    422 => UnprocessableEntity(outObj),
                    _ => BadRequest(outObj)
                };

            }, "GetOTP", skipTokenCheck: false);
        }


        [HttpPost]
        [Route("SendOTPAsync")]//4.
        public async Task<string> SendOTPAsync(string pMobileNo, string pUserName, string pOTP, string pMode, string pLoginAs, string pMpSeatId)
        {
            int sentMsgs = 0;
            int notSentMsgs = 0;
            var logOutput = new StringBuilder();

            try
            {
                string query = "SELECT DISTINCT OTP_SMS_API FROM MP_SEATS WHERE MP_SEAT_ID = @MP_SEAT_ID";
                string? smsApiUrl = Convert.ToString(await _core.ExecScalarAsync(query,
                    new[] { new SqlParameter("@MP_SEAT_ID", pMpSeatId) }));

                if (!string.IsNullOrEmpty(smsApiUrl))
                {
                    string finalUrl = smsApiUrl
                        .Replace("{0}", Uri.EscapeDataString(pMobileNo))
                        .Replace("{1}", Uri.EscapeDataString(pOTP))
                        .Replace("{3}", Uri.EscapeDataString(pLoginAs));

                    if (pMode == "SEND")
                    {
                        try
                        {
                            using var httpClient = new HttpClient();
                            string response = await httpClient.GetStringAsync(finalUrl);

                            sentMsgs++;
                            logOutput.AppendLine($"[SUCCESS] {finalUrl}");
                            logOutput.AppendLine($"Response: {response}");
                        }
                        catch (HttpRequestException httpEx)
                        {
                            notSentMsgs++;
                            logOutput.AppendLine($"[FAIL] {finalUrl}");
                            logOutput.AppendLine($"Error: {httpEx.Message}");
                            LogError(httpEx, "SendOTPAsync - HTTP request error");
                        }
                    }
                }
                else
                {
                    notSentMsgs++;
                    logOutput.AppendLine("No SMS API URL found for the given MP Seat ID.");
                }
            }
            catch (Exception ex)
            {
                logOutput.AppendLine($"[ERROR] Unexpected exception: {ex.Message}");
                LogError(ex, "SendOTPAsync - General Exception");
            }

            return $"Sent: {sentMsgs}, Failed: {notSentMsgs}\n{logOutput}";
        }

        //5.
        [HttpPost("VerifyOTP")]
        public IActionResult VerifyOTP([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                // Step 1: Prepare output wrapper and input dictionary
                var (outObj, rawData) = PrepareWrapperAndData<WrapperObjectData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var selectedKeys = data?.Keys ?? Enumerable.Empty<string>();

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, _, _) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: selectedKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    includeTotalCount: false,
                    includeWhere: false
                );

                // Step 3: Execute stored procedure
                DataTable dt = _core.ExecProcDt("ReactVerifyOTP", paramList.ToArray());

                // // Step 4: Map result to output wrapper
                // ApiHelper.SetSingleRowOutput(dt, outObj);
                // SetOutput(pStatus, pMsg, outObj);

                var resultObject = new Dictionary<string, object>();

                // Always return the input role/mobno
                var otpStatus = new Dictionary<string, string>
                {
                    { "MOBNO", data.TryGetValue("MOBNO", out var mob) ? mob?.ToString() ?? "" : "" },
                    { "ROLE", data.TryGetValue("ROLE", out var role) ? role?.ToString() ?? "" : "" }
                };

                resultObject["OTPStatus"] = otpStatus;

                if (pStatus?.Value?.ToString() == "200")
                {

                }
                else
                {
                    resultObject["MenuRights"] = new List<Dictionary<string, object>>();
                }

                // Set result
                outObj.DataObject = resultObject;
                outObj.StatusCode = int.Parse(pStatus.Value?.ToString() ?? "500");
                outObj.Message = pMsg.Value?.ToString() ?? "Internal Error";



                return outObj;

            }, nameof(VerifyOTP), out _, skipTokenCheck: false));
        }

        //6.

        [HttpPost]
        [Route("GetConstructionWorkDetails")]
        public IActionResult GetConstructionWorkDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Extract search, paging
                var (pSearch, pageIndex, pageSize) = ApiHelper.GetSearchAndPagingObject(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pTotalCount, pWhere) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    includeTotalCount: true,
                    includeWhere: true,
                    pageIndex: pageIndex,
                    pageSize: pageSize
                );

                DataTable dt = _core.ExecProcDt("ReactConstructionWorkDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetConstructionWorkDetails), out _, skipTokenCheck: false));


        }

        //7
        [HttpPost]
        [Route("GetConstructionFormFieldDetails")]
        public IActionResult GetConstructionFormFieldDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, _, _) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    includeTotalCount: false,
                    includeWhere: false

                );

                DataTable dt = _core.ExecProcDt("ReactConstructionFormFieldData", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);



                return outObj;

            }, nameof(GetConstructionFormFieldDetails), out _, skipTokenCheck: false));


        }

        //8
        [HttpPost]
        [Route("GetConstructionStagesDetails")]
        public IActionResult GetConstructionStagesDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, _, _) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    includeTotalCount: true,
                    includeWhere: false

                );

                DataTable dt = _core.ExecProcDt("ReactConstructionStageMasterDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);
                return outObj;

            }, nameof(GetConstructionFormFieldDetails), out _, skipTokenCheck: false));


        }

        //9
        [HttpPost]
        [Route("CrudConstructionWorkDetails")]
        public IActionResult ReactCrudConstructionWorkDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId:pJWT_USERID,
                    includeRetId:false
                );

                DataTable dt = _core.ExecProcDt("ReactCrudConstructionWorkDetails", paramList.ToArray());
                SetOutput(pStatus, pMsg, outObj);
                return outObj;

            }, nameof(GetConstructionFormFieldDetails), out _, skipTokenCheck: false));


        }

    }
}
