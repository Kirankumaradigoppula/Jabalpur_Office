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
using static System.Net.Mime.MediaTypeNames;
using System.Collections.Generic;
using Newtonsoft.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System.Reflection.Emit;
using Microsoft.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using iTextSharp.text;
using iTextSharp.text.pdf;
using System.Drawing;
using System.Net.Http;
using Newtonsoft.Json.Linq;

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

        private readonly IWebHostEnvironment _env;

        private readonly StorageSettings _settings;
        public ProductApiController(AppDbContext context, IsssCore core, JwtTokenHelper jwtToken, IWebHostEnvironment env, IOptions<StorageSettings> settings) : base(context, core, jwtToken, settings)
        {
            _context = context;
            _core = core;
            _jwtTokenHelper = jwtToken;
            _env = env;
            _settings = settings.Value;
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

                //var resultObject = new Dictionary<string, object>
                //{
                //    ["OTPStatus"] = new Dictionary<string, string>
                //    {
                //       { "StatusCode", pStatus?.Value?.ToString() ?? "500" },
                //       { "Message", pMsg?.Value?.ToString() ?? "Internal Error" }
                //    }
                //};

                //// Set result
                //outObj.DataObject = resultObject;
                outObj.StatusCode = int.Parse(pStatus.Value?.ToString() ?? "500");
                outObj.Message = pMsg.Value?.ToString() ?? "Internal Error";
                return outObj;

            }, nameof(VerifyOTP), out _, skipTokenCheck: false));
        }

       

        [HttpPost("GetWebPortalUserMenuRights")]
        public IActionResult GetWebPortalUserMenuRights([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperObjectData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);
                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pTotalCount, _) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId:pJWT_USERID,
                    includeTotalCount: true,
                    includeWhere: false
                );

                DataTable dt = _core.ExecProcDt("ReactWebPortalUserMenuRights", paramList.ToArray());
                //ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);
                //&& data["FLAG"]?.ToString() == "USER_MENU_LIST"
                if (outObj.StatusCode == 200   )
                {
                    var flag = data["FLAG"]?.ToString();

                    var flatMenuList = dt.AsEnumerable()
                        .Select(r => new MenuItem
                        {
                            MENU_MAS_ID = (flag == "USER_MENU_LIST" || flag == "USER_MENU_RIGHTS") ? r["MENU_MAS_ID"].ToString() : null,
                            MENUID = (flag == "USER_MENU_LIST" || flag == "USER_MENU_RIGHTS") ? r["MENUID"].ToString() : null,
                            MENUNM = (flag == "USER_MENU_LIST" || flag == "USER_MENU_RIGHTS") ? r["MENUNM"].ToString() : null,
                            MENUGROUP = (flag == "USER_MENU_LIST" || flag == "USER_MENU_RIGHTS") ? r["MENUGROUP"].ToString() : null,
                            PARENTID = (flag == "USER_MENU_LIST" || flag == "USER_MENU_RIGHTS") ? r["PARENTID"]?.ToString() : null,
                            PARENTMENU = (flag == "USER_MENU_LIST" || flag == "USER_MENU_RIGHTS") ? r["PARENTMENU"]?.ToString() : null,
                            PATH = (flag == "USER_MENU_LIST") ? r["PATH"]?.ToString() : null,
                            ICON = (flag == "USER_MENU_LIST" || flag == "USER_MENU_RIGHTS") ? r["ICON"]?.ToString() : null,
                            MENU_HAS_ACCESS = ( flag == "USER_MENU_RIGHTS") ? Convert.ToInt32(r["MENU_HAS_ACCESS"]) : 0,
                            C_USER_ACCESS = (flag == "USER_MENU_RIGHTS") ? Convert.ToInt32(r["C_USER_ACCESS"]) : 0,
                            U_USER_ACCESS = (flag == "USER_MENU_RIGHTS") ? Convert.ToInt32(r["U_USER_ACCESS"]) : 0,
                            D_USER_ACCESS = (flag == "USER_MENU_RIGHTS") ? Convert.ToInt32(r["D_USER_ACCESS"]) : 0,
                            ID = (flag == "USER_MENU_RIGHTS") ? r["ID"]?.ToString() : null,
                            MENU_RIGHT_ID = (flag == "USER_MENU_RIGHTS") ? r["MENU_RIGHT_ID"]?.ToString() : null,
                            STATUS = r["STATUS"].ToString() == "Y",
                            LEVEL = Convert.ToInt32(r["LEVEL"]),
                            HierarchyPath = r["HierarchyPath"].ToString()
                        })
                        .ToList();

                    // Build lookup
                    //var lookup = flatMenuList
                    //     .GroupBy(x => x.MENUID)
                    //     .ToDictionary(g => g.Key, g => g.First());
                    //
                    var lookup = new Dictionary<string, MenuItem>();
                    foreach (var item in flatMenuList)
                    {
                        // Composite key avoids duplicate key error
                        var key = $"{item.MENUID}|{item.PARENTMENU}|{item.PARENTID}";
                        if (!lookup.ContainsKey(key))
                            lookup[key] = item;
                    }

                    // Build tree
                    var rootItems = new List<MenuItem>();

                    // Step 1: Attach menus according to hierarchy rules
                    foreach (var item in flatMenuList)
                    {
                        if (string.IsNullOrEmpty(item.PARENTMENU) && string.IsNullOrEmpty(item.PARENTID))
                        {
                            rootItems.Add(item); // Root menu
                        }
                        else if (string.IsNullOrEmpty(item.PARENTID) && !string.IsNullOrEmpty(item.PARENTMENU))
                        {
                            // Find parent using composite key
                            var parentKey = $"{item.PARENTMENU}|{""}|{""}";
                            if (lookup.ContainsKey(parentKey))
                                lookup[parentKey].Children.Add(item);
                        }
                        else if (!string.IsNullOrEmpty(item.PARENTID) && !string.IsNullOrEmpty(item.PARENTMENU))
                        {
                            var parentKey = $"{item.PARENTID}|{item.PARENTMENU}|{""}";
                            if (lookup.ContainsKey(parentKey))
                                lookup[parentKey].Children.Add(item);
                        }
                        else
                        {
                            rootItems.Add(item); // fallback
                        }
                    }
                    // Filter inactive recursively
                    void FilterMenu(MenuItem menu)
                    {
                        menu.Children = menu.Children
                            .Where(c => c.STATUS)
                            .OrderBy(c => c.MENUID)
                            .ToList();
                        foreach (var child in menu.Children)
                            FilterMenu(child);
                    }
                    foreach (var root in rootItems.Where(x => x.STATUS))
                        FilterMenu(root);

                    // Convert to dictionary (for JSON output)
                    outObj.DataObject = ConvertToDict(rootItems, flag);
                }
                
                return outObj;


            }, nameof(GetWebPortalUserMenuRights), out _, skipTokenCheck: false));
        }

        List<Dictionary<string, object>> ConvertToDict(List<MenuItem> menus, string flag)
        {
            

            return menus.Select(m =>
            {
                
                var dict = new Dictionary<string, object>();
                // Always include common fields
                dict["MENUID"] = m.MENUID ?? "";
                dict["MENUNM"] = m.MENUNM ?? "";
                dict["MENUGROUP"] = m.MENUGROUP ?? "";
                dict["PARENTID"] = m.PARENTID ?? "";
                dict["PARENTMENU"] = m.PARENTMENU ?? "";

                dict["STATUS"] = m.STATUS ? "Y" : "N";
                dict["LEVEL"] = m.LEVEL.ToString();

                if (flag == "USER_MENU_RIGHTS")
                {
                    dict["MENU_HAS_ACCESS"] = m.MENU_HAS_ACCESS.ToString();
                    dict["C_USER_ACCESS"] = m.C_USER_ACCESS.ToString();
                    dict["U_USER_ACCESS"] = m.U_USER_ACCESS.ToString();
                    dict["D_USER_ACCESS"] = m.D_USER_ACCESS.ToString();
                    dict["ID"] = m.ID ?? "";
                    dict["MENU_RIGHT_ID"] = m.MENU_RIGHT_ID ?? "";
                    dict["ICON"] = m.ICON ?? "";

                }
                if (flag == "USER_MENU_LIST")
                {
                    dict["PATH"] = m.PATH ?? "";
                    dict["ICON"] = m.ICON ?? "";
                }

              

                // Children recursive call (only if not empty)
                var children = ConvertToDict(m.Children, flag);
                if (children.Any())
                {
                    dict["Children"] = children;
                }

                return dict;

            }).ToList();

           

        }


        [HttpPost("CrudWebPortalUserMenuRights")]
        public IActionResult CrudWebPortalUserMenuRights([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudWebPortalUserMenuRights", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudWebPortalUserMenuRights), out _, skipTokenCheck: false));

        }


        //6.

        [HttpPost("GetConstructionWorkDetails")]
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
        [HttpPost("GetConstructionFormFieldDetails")]
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
        [HttpPost("GetConstructionStagesDetails")]
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
        [HttpPost("CrudConstructionWorkDetails_Single")]
        public IActionResult CrudConstructionWorkDetails_Single([FromBody] object input)
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
        

        //10
        [HttpPost("CrudConstructionWorkDetails")]
        //CrudConstructionWorkDetailsWithImage
        public IActionResult CrudConstructionWorkDetails([FromForm] string input, [FromForm] List<IFormFile> files)
        {
            return Ok(ExecuteWithHandling(() =>
            {

                // Remove FILE_STATUS from raw input string
                if (!string.IsNullOrEmpty(input))
                {
                    var jObj = Newtonsoft.Json.Linq.JObject.Parse(input);
                    jObj.Remove("FILE_STATUS");
                    jObj.Remove("P_FILE_STATUS");
                    jObj.Remove("M_FILE_STATUS");
                    input = jObj.ToString();
                }


                var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(
                  string.IsNullOrEmpty(input) ? new { } : ApiHelper.ToObject(input) // deserialize JSON string

                );

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                string cwStagesValue = data.ContainsKey("STAGES_MAS_ID") ? data["STAGES_MAS_ID"]?.ToString() : "0";

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: false
                );

                DataTable dt = _core.ExecProcDt("ReactCrudConstructionWorkDetails", paramList.ToArray());
                SetOutput(pStatus, pMsg, outObj);

                if (outObj.StatusCode == 200 &&  (data["STAGES_MAS_ID"]?.ToString() == "1" || data["STAGES_MAS_ID"]?.ToString() =="7" || data["STAGES_MAS_ID"]?.ToString() == "9"))
                {
                    // Step 1: Validate & handle file uploads
                    if (files != null && files.Count > 0)
                    {
                        // Add FLAG to indicate existing record
                        // You can set the flag value depending on your logic, e.g., "EXISTS" or true/false
                        data["FLAG"] = "SAVE";
                        data["TABLE_FLAG"] = "CONSTRUCTION_WORK";
                        // Convert updated dictionary back to JSON string for CrudConstructionImages
                        string updatedInput = JsonConvert.SerializeObject(data);
                        // Directly call the other method internally
                        var imagesResult = CrudConstructionImages(updatedInput, files) as ObjectResult;

                        // Merge status/message if needed
                        if (imagesResult?.Value is WrapperCrudObjectData imgOut)
                        {
                            outObj.Message += " | " + imgOut.Message;
                        }
                    }
                }
                return outObj;

            }, nameof(CrudConstructionWorkDetails), out _, skipTokenCheck: false));

        }
        
        //10
        [HttpPost("CrudConstructionImages")]
        public IActionResult CrudConstructionImages([FromForm] string input, [FromForm] List<IFormFile> files)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(
                  string.IsNullOrEmpty(input) ? new { } : ApiHelper.ToObject(input) // deserialize JSON string

                );

                var allowedKeys = new[] { "CW_CODE", "STAGES_MAS_ID","DOC_MAS_ID","FLAG","TABLE_FLAG" };

                var data = ApiHelper.ToObjectDictionary(rawData);

                var selectedData = data
                            .Where(kvp => allowedKeys.Contains(kvp.Key))
                            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);



                var filterKeys = ApiHelper.GetFilteredKeys(selectedData);
                string pFLAG = string.Empty;
                string pTABLE_FLAG = string.Empty;
                if (selectedData.ContainsKey("FLAG"))
                {
                    pFLAG = selectedData["FLAG"]?.ToString();
                }
                if (selectedData.ContainsKey("TABLE_FLAG"))
                {
                    pTABLE_FLAG = selectedData["TABLE_FLAG"]?.ToString();
                }
                if (files != null && files.Count > 0 && pFLAG=="SAVE"  )
                {

                    // ✅ Max 5 files
                    if (files.Count > 5)
                    {
                        outObj.StatusCode = 500;
                        outObj.Message = "You can upload a maximum of 5 files.";
                        outObj.LoginStatus = pJWT_LOGIN_NAME;
                        return outObj;
                    }

                    string[] allowedExt = new[] { ".jpg", ".jpeg", ".png", ".pdf" };

                    

                    foreach (var file in files)
                    {
                        string FileName = string.Empty;
                        string FilePath = string.Empty;
                        string ext = string.Empty;
                        if (file.Length > 0)
                        {
                             ext = Path.GetExtension(file.FileName).ToLower();
                            if (!allowedExt.Contains(ext))
                            {
                                outObj.StatusCode = 500;
                                outObj.Message = "Only JPG, PNG, and PDF files are allowed.";
                                outObj.LoginStatus = pJWT_LOGIN_NAME;
                                return outObj;
                            }
                            // ✅ Compute file hash
                            string fileHash;
                            using (var md5 = System.Security.Cryptography.MD5.Create())
                            using (var stream = file.OpenReadStream())
                            {
                                var hash = md5.ComputeHash(stream);
                                fileHash = BitConverter.ToString(hash).Replace("-", "").ToLower();
                            }

                            

                            // ✅ Save fileHash for later DB update
                            selectedData["FILE_HASH"] = fileHash;
                            
                        }
                        // Step 2: Build SQL parameters (advanced dynamic approach)
                        var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                            data: selectedData,
                            keys: filterKeys,
                            mpSeatId: pJWT_MP_SEAT_ID,
                            userId: pJWT_USERID,
                            includeRetId: true
                        );

                        DataTable dt = _core.ExecProcDt("ReactCrudConstructionImages", paramList.ToArray());
                        SetOutputParamsWithRetId(pStatus, pMsg,pRetId, outObj);

                        if (outObj.StatusCode == 200)
                        {                            

                            if (pFLAG =="SAVE")
                            {
                                var storageRoot = _settings.BasePath;
                                string cwCodeValue = null;
                                string cwStagesValue = null;
                                cwCodeValue = selectedData.ContainsKey("CW_CODE") ? selectedData["CW_CODE"]?.ToString() : "UNKNOWN";
                                cwStagesValue = selectedData.ContainsKey("STAGES_MAS_ID") ? selectedData["STAGES_MAS_ID"]?.ToString() : "0";
                                string baseFolder = string.Empty;

                                if (pTABLE_FLAG == "CONSTRUCTION_WORK")
                                {
                                     baseFolder = $"image/MP_{pJWT_MP_SEAT_ID}/Construction/{cwCodeValue}";
                                }
                                if (pTABLE_FLAG == "CONSTRUCTION_INSPECTION")
                                {
                                     baseFolder = $"image/MP_{pJWT_MP_SEAT_ID}/Inspection/{cwCodeValue}";
                                }
                                string finalFolder = Path.Combine(storageRoot, baseFolder);
                                if (!Directory.Exists(finalFolder))
                                {
                                    Directory.CreateDirectory(finalFolder);
                                }

                                // Build file name safely
                                FileName = $"{cwCodeValue}_{cwStagesValue}_{outObj.RetID}{ext}";
                                FilePath = Path.Combine(baseFolder, FileName);
                                string FileFinalPath = Path.Combine(finalFolder, FileName);

                                // ✅ If file already exists, delete it before saving
                                if (System.IO.File.Exists(FileFinalPath))
                                {
                                    System.IO.File.Delete(FileFinalPath);
                                }

                                // ✅ Save the uploaded file to server
                                using (var stream = new FileStream(FileFinalPath, FileMode.Create))
                                {
                                    //await file.CopyToAsync(stream); // file is IFormFile
                                    file.CopyTo(stream); // sync version
                                }
                                // Relative path for DB (use forward slashes)

                                string relativePath = string.Empty;

                                if (pTABLE_FLAG == "CONSTRUCTION_WORK")
                                {
                                     relativePath = $"image/MP_{pJWT_MP_SEAT_ID}/Construction/{cwCodeValue}/{FileName}";
                                }
                                if (pTABLE_FLAG == "CONSTRUCTION_INSPECTION")
                                {
                                    relativePath = $"image/MP_{pJWT_MP_SEAT_ID}/Inspection/{cwCodeValue}/{FileName}";
                                }

                                string vQryUpdateStatus = $"UPDATE CONSTRUCTION_DOCUMENT_MASTER SET FILE_NAME='"+FileName+"' ,FILE_PATH='"+ relativePath + "' WHERE MP_SEAT_ID='"+ pJWT_MP_SEAT_ID + "' AND DOC_MAS_ID='"+ outObj.RetID + "' ";
                                _core.ExecNonQuery(vQryUpdateStatus);
                            }
                        }


                    }

                }
                if (pFLAG == "DELETE")
                {

                        string pFILE_PATH = string.Empty;
                        if (data.ContainsKey("FILE_PATH"))
                        {
                            pFILE_PATH = data["FILE_PATH"]?.ToString();
                        }

                        if (!string.IsNullOrEmpty(pFILE_PATH))
                        {
                            // Step 1: Build SQL parameters (advanced dynamic approach)
                            var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                                data: selectedData,
                                keys: filterKeys,
                                mpSeatId: pJWT_MP_SEAT_ID,
                                userId: pJWT_USERID,
                                includeRetId: true
                            );

                            DataTable dt = _core.ExecProcDt("ReactCrudConstructionImages", paramList.ToArray());
                            SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                            if (outObj.StatusCode == 200)
                            {

                                   // Base folder
                                   string baseFolderPath = _settings.BasePath;

                                    // Build full file path
                                    string fullFilePath = Path.Combine(baseFolderPath, pFILE_PATH.Replace("/", "\\"));
                            // ✅ Step 1: Delete file if exists
                            if (!string.IsNullOrWhiteSpace(fullFilePath) && System.IO.File.Exists(fullFilePath))
                            {
                                System.IO.File.Delete(fullFilePath);
                                // ✅ Step 2: Check parent folder
                                string parentFolder = Path.GetDirectoryName(fullFilePath);
                                if (!string.IsNullOrWhiteSpace(parentFolder) &&
                                         Directory.Exists(parentFolder) &&
                                        !Directory.EnumerateFileSystemEntries(parentFolder).Any())
                                {
                                    Directory.Delete(parentFolder, true); // delete folder if empty
                                }
                            }

                            }
                        }
                }
                return outObj;

            }, nameof(CrudConstructionImages), out _, skipTokenCheck: false));


        }

        //11
        [HttpPost("GetConstructionDocumentMasterDetails")]
        public IActionResult GetConstructionDocumentMasterDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactConstructionDocumentMasterDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);
                return outObj;

            }, nameof(GetConstructionDocumentMasterDetails), out _, skipTokenCheck: false));


        }

        //12
        [HttpPost("CrudConstructionFormFieldDetails")]
        public IActionResult CrudConstructionFormFieldDetails([FromBody] object input)
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
                    userId: pJWT_USERID,
                    includeRetId: false
                );

                DataTable dt = _core.ExecProcDt("ReactCrudConstructionFormFieldMas", paramList.ToArray());
                SetOutput(pStatus, pMsg, outObj);
                return outObj;

            }, nameof(CrudConstructionFormFieldDetails), out _, skipTokenCheck: false));


        }

        //11
        [HttpPost("GetConstructionFormFieldMasterDetails")]
        public IActionResult GetConstructionFormFieldMasterDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactConstructionFormFieldMasterDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);
                
                return outObj;

            }, nameof(GetConstructionFormFieldMasterDetails), out _, skipTokenCheck: false));


        }


        //12
        [HttpPost("GetInspectionProgessStatusDetails")]
        public IActionResult GetInspectionProgessStatusDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactInspectionProgessStatusDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);
                return outObj;

            }, nameof(GetInspectionProgessStatusDetails), out _, skipTokenCheck: false));


        }

        [HttpPost("CrudConstructionInspectionDetails")]
        public IActionResult CrudConstructionInspectionDetails([FromForm] string input, [FromForm] List<IFormFile> files)
        {
            return Ok(ExecuteWithHandling( () =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(
                   string.IsNullOrEmpty(input) ? new { } : ApiHelper.ToObject(input) // deserialize JSON string

                 );

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudConstructionInspectionDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                if (outObj.StatusCode == 200 && files != null && files.Count > 0)
                {

                    data["TABLE_FLAG"] = "CONSTRUCTION_INSPECTION";
                    // Get OTP_SMS_STATUS from DB
                    string pQry = @"SELECT DISTINCT INSPECTION_ID FROM CONSTRUCTION_INSPECTION_DETAILS WHERE MP_SEAT_ID = @MP_SEAT_ID AND ID=@ID";

                    string inspectionId = Convert.ToString(
                       _core.ExecScalarText(
                            pQry,
                             new[] { 
                                 new SqlParameter("@MP_SEAT_ID", pJWT_MP_SEAT_ID) ,
                                 new SqlParameter("@ID", outObj.RetID)

                             }
                        )
                     );
                    data["CW_CODE"] = inspectionId;
                    data["STAGES_MAS_ID"] = Convert.ToString(outObj.RetID);
                    // Convert updated dictionary back to JSON string for CrudConstructionImages
                    string updatedInput = JsonConvert.SerializeObject(data);
                    // Directly call the other method internally
                    var imagesResult = CrudConstructionImages(updatedInput, files) as ObjectResult;

                    //// Merge status/message if needed
                    if (imagesResult?.Value is WrapperCrudObjectData imgOut)
                    {
                        outObj.Message += "  " + imgOut.Message;
                    }
                }
                return outObj;

            }, nameof(CrudConstructionInspectionDetails), out _, skipTokenCheck: false));


        }

        

        [HttpPost("GetConstructionInspectionDetails")]
        public  IActionResult GetConstructionInspectionDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactConstructionInspectionDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetConstructionInspectionDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("GetConstructionInspectionReportDetails")]
        public IActionResult GetConstructionInspectionReportDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactConstructionInspectionReports", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetConstructionInspectionReportDetails), out _, skipTokenCheck: false));

        }



        [HttpPost("CrudConstructionInspectionDelayedDetails")]
        public IActionResult CrudConstructionInspectionDelayedDetails([FromForm] string input, [FromForm] List<IFormFile> files)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(
                   string.IsNullOrEmpty(input) ? new { } : ApiHelper.ToObject(input) // deserialize JSON string

                 );

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, _) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: false
                );

              

                DataTable dt = _core.ExecProcDt("ReactCrudConstructionInspectionDelayedDetails", paramList.ToArray());
                SetOutput(pStatus, pMsg, outObj);
                return outObj;

            }, nameof(CrudConstructionInspectionDetails), out _, skipTokenCheck: false));

        }


        [HttpPost("CrudVisitorConstructionWorkDetails")]
        public IActionResult CrudVisitorConstructionWorkDetails([FromForm] string input, [FromForm] List<IFormFile> files)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(
                   string.IsNullOrEmpty(input) ? new { } : ApiHelper.ToObject(input) // deserialize JSON string

                 );

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudVisitorConstructionWorkDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);

                if (outObj.StatusCode == 200 && files != null && files.Count > 0)
                {
                    string[] allowedExt = new[] { ".jpg", ".jpeg", ".png", ".pdf" };
                    foreach (var file in files)
                    {
                        string FileName = string.Empty;
                        string FilePath = string.Empty;
                        string ext = string.Empty;
                        if (file.Length > 0)
                        {
                            ext = Path.GetExtension(file.FileName).ToLower();
                            if (!allowedExt.Contains(ext))
                            {
                                outObj.StatusCode = 500;
                                outObj.Message = "Only JPG, PNG, and PDF files are allowed.";
                                outObj.LoginStatus = pJWT_LOGIN_NAME;
                                return outObj;
                            }
                            var storageRoot = _settings.BasePath;
                            string baseFolder = string.Empty;
                            baseFolder = $"image/MP_{pJWT_MP_SEAT_ID}/visitorAttachedFiles/";
                            string finalFolder = Path.Combine(storageRoot, baseFolder);
                            if (!Directory.Exists(finalFolder))
                            {
                                Directory.CreateDirectory(finalFolder);
                            }

                            // Build file name safely
                            FileName = $"{pJWT_MP_SEAT_ID}_{outObj.RetID}{ext}";
                            FilePath = Path.Combine(baseFolder, FileName);
                            string FileFinalPath = Path.Combine(finalFolder, FileName);

                            // ✅ If file already exists, delete it before saving
                            if (System.IO.File.Exists(FileFinalPath))
                            {
                                System.IO.File.Delete(FileFinalPath);
                            }

                            // ✅ Save the uploaded file to server
                            using (var stream = new FileStream(FileFinalPath, FileMode.Create))
                            {
                                //await file.CopyToAsync(stream); // file is IFormFile
                                file.CopyTo(stream); // sync version
                            }

                            string vQryUpdateStatus = $"UPDATE VISITOR SET VIS_INWARD_DOCUMENT='" + FileName + "' WHERE MP_SEAT_ID='" + pJWT_MP_SEAT_ID + "' AND VIS_SRNO='" + outObj.RetID + "' ";
                            _core.ExecNonQuery(vQryUpdateStatus);


                        }
                    }
                }
                
                return outObj;

            }, nameof(CrudVisitorConstructionWorkDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("GetConstructionVisitorDetails")]
        public IActionResult GetConstructionVisitorDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactConstructionVisitorDetailsList", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetConstructionVisitorDetails), out _, skipTokenCheck: false));


        }

        [HttpPost("CrudPortalRoleDetails")]
        public IActionResult CrudPortalRoleDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {

                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudPortalRoleDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudPortalRoleDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("GetPortalRoleMasterDetails")]
        public IActionResult GetPortalRoleMasterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters using helper
                var (paramList, pStatus, pMsg, _, _) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    includeTotalCount: false,
                    includeWhere: false
                );

                // Step 3: Execute stored procedure
                DataTable dt = _core.ExecProcDt("ReactPortalRoleMasterDetails", paramList.ToArray());

                // Step 4: Populate output object
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                return outObj;


            }, nameof(GetPortalRoleMasterDetails), out _, skipTokenCheck: false));
        }


        [HttpPost("GetWebPortalUserRegDetails")]
        public IActionResult GetWebPortalUserRegDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactWebPortalUserRegDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                //Get Menu Crud Access For Login Userid 
                if (dt != null && dt.Rows.Count > 0)
                {
                    var row = dt.AsEnumerable().FirstOrDefault(r => r["USERID"]?.ToString() == pJWT_USERID);
                    if (row != null && dt.Columns.Contains("MENU_CRUD_ACCESS"))
                    {
                        outObj.ExtraData["MENU_CRUD_ACCESS"] = row["MENU_CRUD_ACCESS"]?.ToString();
                    }
                }

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetWebPortalUserRegDetails), out _, skipTokenCheck: false));


        }


        [HttpPost("CrudWebPortalUserDetails")]
        public IActionResult CrudWebPortalUserDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {

                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudWebPortalUserDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudWebPortalUserDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("GetReasonMasterDetails")]
        public IActionResult GetReasonMasterDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactReasonMasterDetails", paramList.ToArray());

                // ✅ Convert PURPOSE_LIST into sub-array
                //var list = dt.AsEnumerable().Select(row => new
                //{
                //    REASON_MAS_ID = row["REASON_MAS_ID"],
                //    REASON_NAME = row["REASON_NAME"],
                //    PURPOSES = row["PURPOSE_LIST"]?.ToString()
                //                .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                //                .Select(pid => new {
                //                    PURPOSE_ID = pid.Trim()
                //                    //PURPOSE_NAME = GetPurposeName(pid.Trim()) // 🔹 Lookup method
                //                }).ToList()
                //}).ToList();

                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetReasonMasterDetails), out _, skipTokenCheck: false));


        }


        [HttpPost("CrudReasonMasterDetails")]
        public IActionResult CrudReasonMasterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {

                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudReasonMasterDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudReasonMasterDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("UpdateRowOrderFromCSV")]
        public IActionResult UpdateRowOrderFromCSV([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {

                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, _) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: false
                );

                DataTable dt = _core.ExecProcDt("ReactUpdateRowOrderFromCSV", paramList.ToArray());
                SetOutputParams(pStatus, pMsg,  outObj);
                return outObj;

            }, nameof(UpdateRowOrderFromCSV), out _, skipTokenCheck: false));

        }

        [HttpPost("GetVisitorDetailsList")]
        public IActionResult GetVisitorDetailsList([FromBody] object input)
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

                var pTotalAmount = new SqlParameter("@pTotalAmount", SqlDbType.Int)
                {
                    Direction = ParameterDirection.Output
                };
                paramList.Add(pTotalAmount);

                DataTable dt = _core.ExecProcDt("ReactVisitorDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // Read @pTotalAmount output value safely
                if (pTotalAmount.Value != DBNull.Value)
                {
                    outObj.ExtraData["TotalAmount"] = Convert.ToInt32(pTotalAmount.Value);
                }

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetVisitorDetailsList), out _, skipTokenCheck: false));


        }

        [HttpPost("CrudAppointmentDetails")]
        public IActionResult CrudAppointmentDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {

                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);
                data["ENTRY_FROM"] = "PORTAL";

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudAppointmentDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudAppointmentDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("GetAppointmentDetails")]
        public IActionResult GetAppointmentDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactAppointmentDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetAppointmentDetails), out _, skipTokenCheck: false));


        }

        [HttpPost("GetShokLetterDetails")]
        public IActionResult GetShokLetterDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactShokLetterDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetShokLetterDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("CrudShokLetterDetails")]
        public IActionResult CrudShokLetterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudShokLetterDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudShokLetterDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("GetMediaCategoryDetails")]
        public IActionResult GetMediaCategoryDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactMediaCategoryDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetMediaCategoryDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("CrudMediaCategoryDetails")]
        public IActionResult CrudMediaCategoryDetails([FromForm] string input, [FromForm] List<IFormFile> files)
        {
            return Ok(ExecuteWithHandling(() =>
            {

            var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(
             string.IsNullOrEmpty(input) ? new { } : ApiHelper.ToObject(input) // deserialize JSON string

            );
            var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
            var filterKeys = ApiHelper.GetFilteredKeys(data);
            string pImagePath = string.Empty;

            if (data["FLAG"]?.ToString() == "SAVE")
            {
                if (!(files != null && files.Count > 0))
                {
                    outObj.StatusCode = 500;
                    outObj.Message = "Media Cover file is required.";
                    outObj.LoginStatus = pJWT_LOGIN_NAME;
                    return outObj;
                }
            }
            if (data["FLAG"]?.ToString() == "DELETE")
            {

                string pQry = @"SELECT TOP 1 IMAGE_PATH FROM MEDIA_ALBUM_CATEGORY  WHERE MP_SEAT_ID = @MP_SEAT_ID AND MEDIA_ALBUM_ID=@MEDIA_ALBUM_ID";
                // Get old MEDIA_DATE from DB (before update)
                pImagePath = Convert.ToString(
                     _core.ExecScalarText(
                          pQry,
                           new[] {
                               new SqlParameter("@MP_SEAT_ID", pJWT_MP_SEAT_ID),
                               new SqlParameter("@MEDIA_ALBUM_ID", data["MEDIA_ALBUM_ID"]?.ToString())

                           }
                      )
                   );
            }

            if (data["FLAG"]?.ToString() == "UPDATE")
            {
                string newMediaDate = data["MEDIA_DATE"]?.ToString();
                // Get old MEDIA_DATE from DB
                string oldMediaDate = Convert.ToString(_core.ExecScalarText(
                    @"SELECT TOP 1 FORMAT(MEDIA_DATE,'dd-MM-yyyy') 
                                  FROM MEDIA_ALBUM_CATEGORY  
                                  WHERE MP_SEAT_ID=@MP_SEAT_ID AND MEDIA_ALBUM_ID=@MEDIA_ALBUM_ID",
                                        new[]
                                        {
                                            new SqlParameter("@MP_SEAT_ID", pJWT_MP_SEAT_ID),
                                            new SqlParameter("@MEDIA_ALBUM_ID", data["MEDIA_ALBUM_ID"]?.ToString())
                                        }
                ));

                if (!string.IsNullOrEmpty(oldMediaDate) && oldMediaDate != newMediaDate)
                {
                    // Move all images for this album to new MEDIA_DATE folder
                    string oldFolder = Path.Combine(_settings.BasePath, $"image/MP_{pJWT_MP_SEAT_ID}/MediaAlbums/{oldMediaDate}");
                    string newFolder = Path.Combine(_settings.BasePath, $"image/MP_{pJWT_MP_SEAT_ID}/MediaAlbums/{newMediaDate}");
                    string pMediaAlbumId = data["MEDIA_ALBUM_ID"]?.ToString();

                    if (!Directory.Exists(newFolder))
                        Directory.CreateDirectory(newFolder);
                        /* Start Media Cover Image */
                        string pMCqry = @"
                           SELECT  IMAGE, IMAGE_PATH
                           FROM MEDIA_ALBUM_CATEGORY
                           WHERE MP_SEAT_ID = @SeatId
                             AND MEDIA_ALBUM_ID = @AlbumId";

                        DataTable dtCoverImages = _core.ExecDtText(
                            pMCqry,
                            new[]
                            {
                                  new SqlParameter("@SeatId", pJWT_MP_SEAT_ID),
                                  new SqlParameter("@AlbumId", pMediaAlbumId),
                            }
                        );
                        foreach (DataRow row in dtCoverImages.Rows)
                        {
                            string oldFilePath = Path.Combine(_settings.BasePath, row["IMAGE_PATH"].ToString().Replace("/", "\\"));
                            if (System.IO.File.Exists(oldFilePath))
                            {
                                string newFilePath = Path.Combine(newFolder, row["IMAGE"].ToString());
                                System.IO.File.Move(oldFilePath, newFilePath);

                                string newRelativePath = $"image/MP_{pJWT_MP_SEAT_ID}/MediaAlbums/{newMediaDate}/{row["IMAGE"]}";

                                string vQryNewMCPathStatus = $"UPDATE MEDIA_ALBUM_CATEGORY SET IMAGE_PATH='" + newRelativePath + "' WHERE MP_SEAT_ID='" + pJWT_MP_SEAT_ID + "' AND MEDIA_ALBUM_ID='" + pMediaAlbumId + "' ";
                                _core.ExecNonQuery(vQryNewMCPathStatus);

                            }
                        }

                        /* End Media Cover Image */
                        /* Start Medial Album Details  -29-09-2025*/
                        string pMqry = @"
                           SELECT MEDIA_ALBUM_DET_ID, IMAGE, IMAGE_PATH
                           FROM MEDIA_ALBUM_DETAILS
                           WHERE MP_SEAT_ID = @SeatId
                             AND MEDIA_ALBUM_ID = @AlbumId";

                    // Get all images for this album
                         DataTable dtImages = _core.ExecDtText(
                           pMqry,
                           new[]
                           {
                               new SqlParameter("@SeatId", pJWT_MP_SEAT_ID),
                               new SqlParameter("@AlbumId", pMediaAlbumId),
                           }
                          );


                        foreach (DataRow row in dtImages.Rows)
                        {
                            string oldFilePath = Path.Combine(_settings.BasePath, row["IMAGE_PATH"].ToString().Replace("/", "\\"));
                            if (System.IO.File.Exists(oldFilePath))
                            {
                                string newFilePath = Path.Combine(newFolder, row["IMAGE"].ToString());
                                System.IO.File.Move(oldFilePath, newFilePath);

                                string newRelativePath = $"image/MP_{pJWT_MP_SEAT_ID}/MediaAlbums/{newMediaDate}/{row["IMAGE"]}";

                                string vQryNewPathStatus = $"UPDATE MEDIA_ALBUM_DETAILS SET IMAGE_PATH='" + newRelativePath + "' WHERE MP_SEAT_ID='" + pJWT_MP_SEAT_ID + "' AND MEDIA_ALBUM_DET_ID='" + row["MEDIA_ALBUM_DET_ID"] + "' ";
                                _core.ExecNonQuery(vQryNewPathStatus);

                            }
                        }
                   /* End Media Album Details  -29-09-2025*/
                        // Remove old folder if empty
                        if (Directory.Exists(oldFolder) && !Directory.EnumerateFileSystemEntries(oldFolder).Any())
                            Directory.Delete(oldFolder, true);
                    }

                }

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudMediaCategoryDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                if (outObj.StatusCode == 200)
                {
                    if (data["FLAG"]?.ToString() == "SAVE" || data["FLAG"]?.ToString() == "UPDATE")
                    {
                        
                        if (files != null && files.Count > 0)
                        {
                            if (files.Count > 1)
                            {
                                outObj.StatusCode = 500;
                                outObj.Message = "You can upload a maximum of One files.";
                                outObj.LoginStatus = pJWT_LOGIN_NAME;
                                return outObj;
                            }
                            //string[] allowedExt = new[] { ".jpg", ".jpeg", ".png", ".pdf" };
                            foreach (var file in files)
                            {
                                
                                string FileName = string.Empty;
                                string FilePath = string.Empty;
                                string ext = string.Empty;
                                if (file.Length > 0)
                                {
                                    var storageRoot = _settings.BasePath;
                                    string baseFolder = string.Empty;
                                    ext = Path.GetExtension(file.FileName).ToLower();
                                    baseFolder = $"image/MP_{pJWT_MP_SEAT_ID}/MediaAlbums/{data["MEDIA_DATE"]}/";
                                    string finalFolder = Path.Combine(storageRoot, baseFolder);
                                    if (!Directory.Exists(finalFolder))
                                    {
                                        Directory.CreateDirectory(finalFolder);
                                    }
                                    // Build file name safely
                                    FileName = $"Media_Cover_{outObj.RetID}{ext}";
                                    FilePath = Path.Combine(baseFolder, FileName);
                                    string FileFinalPath = Path.Combine(finalFolder, FileName);
                                    // ✅ If file already exists, delete it before saving
                                    if (System.IO.File.Exists(FileFinalPath))
                                    {
                                        System.IO.File.Delete(FileFinalPath);
                                    }

                                    // ✅ Save the uploaded file to server
                                    using (var stream = new FileStream(FileFinalPath, FileMode.Create))
                                    {
                                        //await file.CopyToAsync(stream); // file is IFormFile
                                        file.CopyTo(stream); // sync version
                                    }
                                    // Relative path for DB (use forward slashes)

                                    string relativePath = string.Empty;
                                    relativePath = $"image/MP_{pJWT_MP_SEAT_ID}/MediaAlbums/{data["MEDIA_DATE"]}/{FileName}";

                                    string vQryUpdateStatus = $"UPDATE MEDIA_ALBUM_CATEGORY SET IMAGE='" + FileName + "' ,IMAGE_PATH='" + relativePath + "' WHERE MP_SEAT_ID='" + pJWT_MP_SEAT_ID + "' AND MEDIA_ALBUM_ID='" + outObj.RetID + "' ";
                                    _core.ExecNonQuery(vQryUpdateStatus);


                                }
                            }
                        }
                    }
                    if (data["FLAG"]?.ToString() == "DELETE")
                    {
                        
                        // Base folder
                        string baseFolderPath = _settings.BasePath;

                        // Build full file path
                        string fullFilePath = Path.Combine(baseFolderPath, pImagePath.Replace("/", "\\"));
                        if (!string.IsNullOrWhiteSpace(fullFilePath) && System.IO.File.Exists(fullFilePath))
                        {
                            System.IO.File.Delete(fullFilePath);
                            // ✅ Step 2: Check parent folder
                            string parentFolder = Path.GetDirectoryName(fullFilePath);
                            if (!string.IsNullOrWhiteSpace(parentFolder) &&
                                     Directory.Exists(parentFolder) &&
                                    !Directory.EnumerateFileSystemEntries(parentFolder).Any())
                            {
                                Directory.Delete(parentFolder, true); // delete folder if empty
                            }
                        }
                    }
                }
                return outObj;

            }, nameof(CrudMediaCategoryDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("CrudMediaAlbumDetails")]
        public IActionResult CrudMediaAlbumDetails([FromForm] string input, [FromForm] List<IFormFile> files)
        {
            return Ok(ExecuteWithHandling(() =>
            {

                var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(
                 string.IsNullOrEmpty(input) ? new { } : ApiHelper.ToObject(input) // deserialize JSON string

                );
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);
                string pImagePath = string.Empty;

                if (data["FLAG"]?.ToString() == "SAVE" || data["FLAG"]?.ToString() == "UPDATE")
                {
                    if (!(files != null && files.Count > 0))
                    {
                        outObj.StatusCode = 500;
                        outObj.Message = "Media Album file is required.";
                        outObj.LoginStatus = pJWT_LOGIN_NAME;
                        return outObj;
                    }
                    if (files != null && files.Count > 0)
                    {
                        // ✅ Max 5 files
                        if (files.Count > 100)
                        {
                            outObj.StatusCode = 500;
                            outObj.Message = "You can upload a maximum of 100 files.";
                            outObj.LoginStatus = pJWT_LOGIN_NAME;
                            return outObj;
                        }
                        string[] allowedExt = new[] { ".jpg", ".jpeg", ".JPEG", ".png", ".pdf" };

                        foreach (var file in files)
                        {
                            string FileName = string.Empty;
                            string FilePath = string.Empty;
                            string ext = string.Empty;
                            if (file.Length > 0)
                            {
                                ext = Path.GetExtension(file.FileName).ToLower();
                                if (!allowedExt.Contains(ext))
                                {
                                    outObj.StatusCode = 500;
                                    outObj.Message = "Only JPG, PNG, and PDF files are allowed.";
                                    outObj.LoginStatus = pJWT_LOGIN_NAME;
                                    return outObj;
                                }

                            }
                            // Step 2: Build SQL parameters (advanced dynamic approach)
                            var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                                data: data,
                                keys: filterKeys,
                                mpSeatId: pJWT_MP_SEAT_ID,
                                userId: pJWT_USERID,
                                includeRetId: true
                            );
                            DataTable dt = _core.ExecProcDt("ReactCrudMediaAlbumDetails", paramList.ToArray());
                            SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                            if (outObj.StatusCode == 200)
                            {
                                try
                                {
                                    // 🔹 Get MEDIA_DATE (old date if update)
                                    string pMedia_Date = Convert.ToString(_core.ExecScalarText(
                                        @"SELECT TOP 1 FORMAT(MEDIA_DATE,'dd-MM-yyyy') 
                                        FROM MEDIA_ALBUM_CATEGORY  
                                        WHERE MP_SEAT_ID=@MP_SEAT_ID AND MEDIA_ALBUM_ID=@MEDIA_ALBUM_ID",
                                        new[] {
                                         new SqlParameter("@MP_SEAT_ID", pJWT_MP_SEAT_ID),
                                         new SqlParameter("@MEDIA_ALBUM_ID", data["MEDIA_ALBUM_ID"]?.ToString())
                                        }
                                    ));

                                    if (data["FLAG"]?.ToString() == "UPDATE")
                                    {
                                        string pQry = @"SELECT TOP 1 IMAGE_PATH FROM MEDIA_ALBUM_DETAILS  WHERE MP_SEAT_ID = @MP_SEAT_ID AND MEDIA_ALBUM_ID=@MEDIA_ALBUM_ID AND MEDIA_ALBUM_DET_ID=@MEDIA_ALBUM_DET_ID";
                                        // Get old MEDIA_DATE from DB (before update)
                                        pImagePath = Convert.ToString(
                                             _core.ExecScalarText(
                                                  pQry,
                                                   new[] {
                                                   new SqlParameter("@MP_SEAT_ID", pJWT_MP_SEAT_ID) ,
                                                   new SqlParameter("@MEDIA_ALBUM_ID",data["MEDIA_ALBUM_ID"]?.ToString()),
                                                   new SqlParameter("@MEDIA_ALBUM_DET_ID",data["MEDIA_ALBUM_DET_ID"]?.ToString())

                                                   }
                                              )
                                           );


                                        string baseFolderPath = _settings.BasePath;
                                        // Build full file path
                                        string fullFilePath = Path.Combine(baseFolderPath, pImagePath.Replace("/", "\\"));
                                        if (!string.IsNullOrWhiteSpace(fullFilePath) && System.IO.File.Exists(fullFilePath))
                                        {
                                            System.IO.File.Delete(fullFilePath);
                                           
                                        }

                                    }

                                    var storageRoot = _settings.BasePath;
                                    string baseFolder = string.Empty;
                                    baseFolder = $"image/MP_{pJWT_MP_SEAT_ID}/MediaAlbums/{pMedia_Date}";
                                    string finalFolder = Path.Combine(storageRoot, baseFolder);
                                    if (!Directory.Exists(finalFolder))
                                    {
                                        Directory.CreateDirectory(finalFolder);
                                    }
                                    if (!Directory.Exists(finalFolder))
                                    {
                                        Directory.CreateDirectory(finalFolder);
                                    }

                                    FileName = Path.GetFileName(file.FileName).Replace(" ", "_").Replace("(", "_").Replace(")", "").Replace("'", "");
                                    FilePath = Path.Combine(baseFolder, FileName);
                                    string FileFinalPath = Path.Combine(finalFolder, FileName);

                                    // ✅ If file already exists, delete it before saving
                                    if (System.IO.File.Exists(FileFinalPath))
                                    {
                                        System.IO.File.Delete(FileFinalPath);
                                    }

                                    // ✅ Save the uploaded file to server
                                    using (var stream = new FileStream(FileFinalPath, FileMode.Create))
                                    {
                                        //await file.CopyToAsync(stream); // file is IFormFile
                                        file.CopyTo(stream); // sync version
                                    }
                                    // Relative path for DB (use forward slashes)

                                    string relativePath = $"image/MP_{pJWT_MP_SEAT_ID}/MediaAlbums/{pMedia_Date}/{FileName}";

                                    string vQryUpdateStatus = $"UPDATE MEDIA_ALBUM_DETAILS SET IMAGE=N'" + FileName + "' ,IMAGE_PATH=N'" + relativePath + "' WHERE MP_SEAT_ID='" + pJWT_MP_SEAT_ID + "' AND MEDIA_ALBUM_DET_ID='" + outObj.RetID + "' ";
                                    _core.ExecNonQuery(vQryUpdateStatus);
                                }
                                catch(Exception Ex)
                                {
                                    string delQry = $"DELETE FROM MEDIA_ALBUM_DETAILS WHERE MP_SEAT_ID={pJWT_MP_SEAT_ID} AND MEDIA_ALBUM_DET_ID='" + outObj.RetID + "' ";
                                    _core.ExecNonQuery(delQry);
                                    outObj.StatusCode = 500;
                                    outObj.Message = "File upload failed. Record has been removed.";
                                    outObj.LoginStatus = pJWT_LOGIN_NAME;
                                }


                            }

                        }


                    }
                }
                if (data["FLAG"]?.ToString() == "DELETE" || data["FLAG"]?.ToString() == "UPDATE_DESCRIPTION")
                {
                    // Step 2: Build SQL parameters (advanced dynamic approach)
                    var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                        data: data,
                        keys: filterKeys,
                        mpSeatId: pJWT_MP_SEAT_ID,
                        userId: pJWT_USERID,
                        includeRetId: true
                    );
                    DataTable dt = _core.ExecProcDt("ReactCrudMediaAlbumDetails", paramList.ToArray());
                    SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                    if (outObj.StatusCode == 200)
                    {
                        if (data["FLAG"]?.ToString() == "DELETE")
                        {
                            string pQry = @"SELECT TOP 1 IMAGE_PATH FROM MEDIA_ALBUM_DETAILS  WHERE MP_SEAT_ID = @MP_SEAT_ID AND MEDIA_ALBUM_ID=@MEDIA_ALBUM_ID AND MEDIA_ALBUM_DET_ID=@MEDIA_ALBUM_DET_ID";
                            pImagePath = Convert.ToString(
                                      _core.ExecScalarText(
                                           pQry,
                                            new[] {
                                            new SqlParameter("@MP_SEAT_ID", pJWT_MP_SEAT_ID) ,
                                            new SqlParameter("@MEDIA_ALBUM_ID",data["MEDIA_ALBUM_ID"]?.ToString()),
                                            new SqlParameter("@MEDIA_ALBUM_DET_ID",data["MEDIA_ALBUM_DET_ID"]?.ToString())

                                            }
                                       )
                                   );


                            string baseFolderPath = _settings.BasePath;
                            // Build full file path
                            string fullFilePath = Path.Combine(baseFolderPath, pImagePath.Replace("/", "\\"));
                            if (!string.IsNullOrWhiteSpace(fullFilePath) && System.IO.File.Exists(fullFilePath))
                            {
                                System.IO.File.Delete(fullFilePath);

                                string parentFolder = Path.GetDirectoryName(fullFilePath);
                                if (!string.IsNullOrWhiteSpace(parentFolder) &&
                                         Directory.Exists(parentFolder) &&
                                        !Directory.EnumerateFileSystemEntries(parentFolder).Any())
                                {
                                    Directory.Delete(parentFolder, true); // delete folder if empty
                                }

                            }
                        }
                    }
                }

                return outObj;
                
            }, nameof(CrudMediaAlbumDetails), out _, skipTokenCheck: false));
        }


        [HttpPost("DownloadImagesAsPdf")]
        public IActionResult DownloadImagesAsPdf([FromBody] object input)
        {
            var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

            var data = ApiHelper.ToObjectDictionary(rawData);
            var filterKeys = ApiHelper.GetFilteredKeys(data);

            var (paramList, pStatus, pMsg, _, _) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                data: data,
                keys: filterKeys,
                mpSeatId: pJWT_MP_SEAT_ID,
                includeTotalCount: false,
                includeWhere: false
            );

            DataTable dtImages = _core.ExecProcDt("ReactImagesAsPdf", paramList.ToArray());

            if (dtImages.Rows.Count == 0)
                return NotFound("No images found.");

            string pID = data["ID"].ToString();
            byte[] pdfBytes;

            using (var ms = new MemoryStream())
            using (var doc = new iTextSharp.text.Document())
            {
                iTextSharp.text.pdf.PdfWriter.GetInstance(doc, ms);
                doc.Open();

                foreach (DataRow row in dtImages.Rows)
                {
                    string imagePath = row["IMAGE_PATH"].ToString();
                    string heading = row["IMAGE_TITLE"].ToString();
                    string fullPath = Path.Combine(_settings.BasePath, imagePath.Replace("/", "\\"));

                    if (System.IO.File.Exists(fullPath))
                    {
                        var font = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 14, BaseColor.Black);
                        doc.Add(new Paragraph(heading, font));
                        doc.Add(new Paragraph("\n"));

                        var image = iTextSharp.text.Image.GetInstance(fullPath);
                        image.ScaleToFit(doc.PageSize.Width - 40, doc.PageSize.Height - 40);
                        image.Alignment = iTextSharp.text.Image.ALIGN_CENTER;
                        doc.Add(image);

                        doc.NewPage();
                    }
                }
                doc.Close();
                pdfBytes = ms.ToArray();
            }

            return File(pdfBytes, "application/pdf", $"MediaAlbum_{pID}.pdf");
        }

        [HttpPost("GetAllNameMobnoDetails")]
        public IActionResult GetAllNameMobnoDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactAllNameMobno", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);
                return outObj;

            }, nameof(GetAllNameMobnoDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("SendSMSService")]

        public async Task<WrapperListData> SendSMSService([FromBody] object input)
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

            DataTable dt = _core.ExecProcDt("ReactSMSServiceDetails", paramList.ToArray());
            ApiHelper.SetDataTableListOutput(dt, outObj);
            SetOutput(pStatus, pMsg, outObj);
            if (outObj.StatusCode == 200 && dt != null && dt.Rows.Count > 0)
            {
                // don’t populate DataList, just use dt for config
                outObj.DataList = null;
                string smsApiUrl = dt.Rows[0]["SMS_API"].ToString();
                string smsBalApiUrl = dt.Rows[0]["SMS_BALANCE_API"].ToString();

                if (!string.IsNullOrEmpty(smsApiUrl) && data.ContainsKey("MOBNO_LIST"))
                {

                    // 🔹 Step 1: Get balance ONCE
                    string balanceValue = "";
                    try
                    {
                        using var client = new HttpClient();
                        string jsonString = await client.GetStringAsync(smsBalApiUrl);
                        JObject jsonObject = JObject.Parse(jsonString);
                        balanceValue = (string)jsonObject["balance"];
                    }
                    catch (Exception ex)
                    {
                        balanceValue = "ERROR: " + ex.Message;
                    }

                    // 🔹 Step 2: Prepare numbers
                    string mobNoList = data["MOBNO_LIST"]?.ToString() ?? string.Empty;
                    // Split by comma, trim whitespace
                    List<string> mobileNumbers = mobNoList.Split(',')
                          .Select(x => x.Trim())
                          .Where(x => !string.IsNullOrWhiteSpace(x))
                          .ToList();

                    int successCount = 0;
                    int failureCount = 0;
                    using var httpClient = new HttpClient();

                    // 🔹 Step 3: Send SMS in parallel
                    var tasks = mobileNumbers.Select(async mob =>
                    {
                        string finalUrl = smsApiUrl.Replace("{0}", Uri.EscapeDataString(mob));
                       
                        try
                        {
                            HttpResponseMessage response = await httpClient.GetAsync(finalUrl);
                            if (response.IsSuccessStatusCode)
                            {
                                string responseContent = await response.Content.ReadAsStringAsync();
                                Interlocked.Increment(ref successCount);
                                Console.WriteLine($"✅ SMS sent to {mob}. API Response: {responseContent}");
                            }
                            else
                            {
                                Interlocked.Increment(ref failureCount);
                                Console.WriteLine($"❌ Failed for {mob}. StatusCode: {response.StatusCode}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Interlocked.Increment(ref failureCount);
                            Console.WriteLine($"⚠️ Error while sending SMS to {mob}: {ex.Message}");
                        }
                    });
                    await Task.WhenAll(tasks);
                    // 📊 Aggregate result
                    int totalNumbers = mobileNumbers.Count;

                    outObj.ExtraData["SMS_SERVICE_DETAILS"] = new
                    {
                        TotalNumbers = totalNumbers,
                        TotalSent = successCount,
                        TotalFailed = failureCount

                    };
                    // 📝 Log into DB
                    string flag = data.ContainsKey("FLAG") ? data["FLAG"]?.ToString() ?? "" : "";
                    string MAS_ID = null;
                    if (data.ContainsKey("MAS_ID") && !string.IsNullOrWhiteSpace(data["MAS_ID"]?.ToString()))
                    {
                        MAS_ID = data["MAS_ID"].ToString();
                    }
                    string vQryStatus = $@"
                    INSERT INTO DAILY_SMS_LOG_MASTER 
                    (MP_SEAT_ID, DAILY_SMS_TYPE, DAILY_SMS_TOTAL_COUNT,DAILY_SMS_MOBILE_NO_LIST,SMS_BALANCE,OTHER_TABLE_MAS_ID) 
                    VALUES ('{pJWT_MP_SEAT_ID}', '{flag}', {totalNumbers},'{mobNoList}','{balanceValue}','{MAS_ID}')";
                    _core.ExecNonQuery(vQryStatus);

                    if (flag == "APPOINTMENT")
                    {
                        string vQryUpdateStatus = $@"
                             UPDATE MP_APPOINTMENT 
                             SET SMS_STATUS='Y'  
                             WHERE MP_SEAT_ID='{pJWT_MP_SEAT_ID}' 
                             AND APPOINTMENT_STATUS='ACCEPTED' 
                             AND SMS_STATUS IS NULL
                             AND (MOBNO IN ({string.Join(",", mobileNumbers.Select(m => $"'{m}'"))})
                                  OR ALTR_MOBNO IN ({string.Join(",", mobileNumbers.Select(m => $"'{m}'"))}))";
                        _core.ExecNonQuery(vQryUpdateStatus);
                      
                    }

                }
            }
            return outObj;

           
        }

        [HttpPost("GetBirthdayDetails")]
        public IActionResult GetBirthdayDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactBirthdayDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetBirthdayDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("GetAnniversaryDetails")]
        public IActionResult GetAnniversaryDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactAnniversaryDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetAnniversaryDetails), out _, skipTokenCheck: false));
        }

        //Pending
        [HttpPost("CrudAnniversaryBirthdayDetails")]
        public IActionResult CrudAnniversaryBirthdayDetails([FromForm] string input, [FromForm] List<IFormFile> files)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(
                         string.IsNullOrEmpty(input) ? new { } : ApiHelper.ToObject(input) // deserialize JSON string

                );
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);
                string pImagePath = string.Empty;
                return outObj;
            }, nameof(GetAnniversaryDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("GetSwechchmadMasterDetails")]
        public IActionResult GetSwechchmadMasterDetails([FromBody] object input)
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

                var pTotalAmount = new SqlParameter("@pTotalAmount", SqlDbType.Decimal)
                {
                    Precision = 18,
                    Scale = 2,
                    Direction = ParameterDirection.Output
                };
                paramList.Add(pTotalAmount);
                var pTotalAspectAmount = new SqlParameter("@pTotalAspectAmount", SqlDbType.Decimal)
                {
                    Precision = 18,
                    Scale = 2,
                    Direction = ParameterDirection.Output
                };
                paramList.Add(pTotalAspectAmount);
                DataTable dt = _core.ExecProcDt("ReactSwechchmadMasterDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                if (outObj.StatusCode ==200)
                {
                    if (pTotalAmount.Value != DBNull.Value)
                    {
                        outObj.ExtraData["TotalAmount"] = Convert.ToDecimal(pTotalAmount.Value);
                    }
                    if (pTotalAspectAmount.Value != DBNull.Value)
                    {
                        outObj.ExtraData["TotalAspectAmount"] = Convert.ToDecimal(pTotalAspectAmount.Value);
                    }
                 
                }

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetSwechchmadMasterDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("CrudSwechchmadMasterDetails")]
        public IActionResult CrudSwechchmadMasterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudSwechchmadMasterDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;
            }, nameof(CrudSwechchmadMasterDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("CrudSwechchmadDocumentDetails")]
        public IActionResult CrudSwechchmadDocumentDetails([FromForm] string input, [FromForm] List<IFormFile> files)
        {
            return Ok(ExecuteWithHandling(() =>
            {

                var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(
                     string.IsNullOrEmpty(input) ? new { } : ApiHelper.ToObject(input) // deserialize JSON string

                 );
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);
                string pImagePath = string.Empty;
                string flag = data.ContainsKey("FLAG") ? data["FLAG"]?.ToString() ?? "" : "";

                if (flag == "SAVE" )
                {
                    if (files == null || files.Count == 0)
                    {
                        outObj.StatusCode = 500;
                        outObj.Message = "PDF file is required.";
                        outObj.LoginStatus = pJWT_LOGIN_NAME;
                        return outObj;
                    }

                    if (files.Count > 1)
                    {
                        outObj.StatusCode = 500;
                        outObj.Message = "Only one PDF file can be uploaded.";
                        outObj.LoginStatus = pJWT_LOGIN_NAME;
                        return outObj;
                    }

                    var file = files.First();
                    string ext = Path.GetExtension(file.FileName).ToLower();
                    if (ext != ".pdf")
                    {
                        outObj.StatusCode = 500;
                        outObj.Message = "Only PDF files are allowed.";
                        outObj.LoginStatus = pJWT_LOGIN_NAME;
                        return outObj;
                    }
                }

                if (flag == "DELETE")
                {
                    string pQry = @"SELECT TOP 1 FILEPATH FROM SWECCHAMAD_DOCUMENTS  WHERE MP_SEAT_ID = @MP_SEAT_ID AND ID=@ID";
                    // Get old MEDIA_DATE from DB (before update)
                    pImagePath = Convert.ToString(
                         _core.ExecScalarText(
                              pQry,
                               new[] {
                       new SqlParameter("@MP_SEAT_ID", pJWT_MP_SEAT_ID),
                       new SqlParameter("@ID", data["ID"]?.ToString())

                               }
                          )
                       );
                }

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudSwechchmadDocumentDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                if (outObj.StatusCode == 200)
                {
                    if (flag == "SAVE" || flag == "UPDATE")
                    {
                        if (files.Count > 1)
                        {
                            outObj.StatusCode = 500;
                            outObj.Message = "You can upload a maximum of One file.";
                            outObj.LoginStatus = pJWT_LOGIN_NAME;
                            return outObj;
                        }
                        if (files != null && files.Count == 1)
                        {

                            var file = files.First();
                            string ext = Path.GetExtension(file.FileName).ToLower();
                            // Double-check PDF only
                            if (ext != ".pdf")
                            {
                                outObj.StatusCode = 500;
                                outObj.Message = "Only PDF files are allowed.";
                                outObj.LoginStatus = pJWT_LOGIN_NAME;
                                return outObj;
                            }

                            string storageRoot = _settings.BasePath;
                            string baseFolder = Path.Combine("image", $"MP_{pJWT_MP_SEAT_ID}", "SWECCHAMAD", data["PARENT_MAS_ID"].ToString());
                            string finalFolder = Path.Combine(storageRoot, baseFolder);
                            if (!Directory.Exists(finalFolder))
                            {
                                Directory.CreateDirectory(finalFolder);
                            }

                            string fileName = $"SW_{data["PARENT_MAS_ID"]}_{outObj.RetID}{ext}";
                            string relativePath = Path.Combine(baseFolder, fileName).Replace("\\", "/");
                            string fullPath = Path.Combine(finalFolder, fileName);

                            // ✅ If file already exists, delete it before saving
                            if (System.IO.File.Exists(fullPath))
                            {
                                System.IO.File.Delete(fullPath);
                            }
                            using (var stream = new FileStream(fullPath, FileMode.Create))
                            {
                                file.CopyTo(stream);
                            }

                            // Update DB safely
                            string updateQry = $"UPDATE SWECCHAMAD_DOCUMENTS SET DOC_NAME = '" + fileName + "', FILEPATH = '"+relativePath+ "' WHERE MP_SEAT_ID='" + pJWT_MP_SEAT_ID + "' AND ID='"+ outObj.RetID + "' ";
                            _core.ExecNonQuery(updateQry);
                        }
                    }
                    if (flag == "DELETE" && !string.IsNullOrEmpty(pImagePath))
                    {
                        string baseFolderPath = _settings.BasePath;
                        string fullFilePath = Path.Combine(baseFolderPath, pImagePath.Replace("/", "\\"));

                        if (System.IO.File.Exists(fullFilePath))
                        {
                            System.IO.File.Delete(fullFilePath);

                            string parentFolder = Path.GetDirectoryName(fullFilePath);
                            if (!string.IsNullOrEmpty(parentFolder) &&
                                Directory.Exists(parentFolder) &&
                                !Directory.EnumerateFileSystemEntries(parentFolder).Any())
                            {
                                Directory.Delete(parentFolder, true);
                            }
                        }

                    }
                }
                return outObj;
            }, nameof(CrudSwechchmadDocumentDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("GetSwechchmadDocumentDetails")]
        public IActionResult GetSwechchmadDocumentDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactSwechchmadDocumentDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);
                return outObj;
            }, nameof(GetSwechchmadDocumentDetails), out _, skipTokenCheck: false));
        }



        [HttpPost("GetSwechchmadDetails")]
        public IActionResult GetSwechchmadDetails([FromBody] object input)
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

                var pTotalAmount = new SqlParameter("@pTotalAmount", SqlDbType.Decimal)
                {
                    Precision = 18,
                    Scale = 2,
                    Direction = ParameterDirection.Output
                };
                paramList.Add(pTotalAmount);
                var pTotalAspectAmount = new SqlParameter("@pTotalAspectAmount", SqlDbType.Decimal)
                {
                    Precision = 18,
                    Scale = 2,
                    Direction = ParameterDirection.Output
                };
                paramList.Add(pTotalAspectAmount);
                DataTable dt = _core.ExecProcDt("ReactSwechchmadDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                if (outObj.StatusCode == 200)
                {
                    if (pTotalAmount.Value != DBNull.Value)
                    {
                        outObj.ExtraData["TotalAmount"] = Convert.ToDecimal(pTotalAmount.Value);
                    }
                    if (pTotalAspectAmount.Value != DBNull.Value)
                    {
                        outObj.ExtraData["TotalAspectAmount"] = Convert.ToDecimal(pTotalAspectAmount.Value);
                    }

                }

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetSwechchmadDetails), out _, skipTokenCheck: false));
        }


        [HttpPost("CrudSwechchmadDetails")]
        public IActionResult CrudSwechchmadDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {

                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudSwechchmadDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;
            }, nameof(CrudSwechchmadDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("GetUddhesyaMasDetails")]
        public IActionResult GetUddhesyaMasDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactCrudUddeshyaMasDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetUddhesyaMasDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("CrudUddheshyaMasDetails")]
        public IActionResult CrudUddheshyaMasDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudUddeshyaMasDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudUddheshyaMasDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("GetProfessionDetails")]
        public IActionResult GetProfessionDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactProfessionDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetProfessionDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("CrudProfessionDetails")]
        public IActionResult CrudProfessionDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudProfessionDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudProfessionDetails), out _, skipTokenCheck: false));

        }


        [HttpPost("GetDesignationMasterDetails")]
        public IActionResult GetDesignationMasterDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactDesignationDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetDesignationMasterDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("CrudDesignationMasterDetails")]
        public IActionResult CrudDesignationMasterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudDesignationMasterDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudDesignationMasterDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("CrudDepartmentMasterDetails")]
        public IActionResult CrudDepartmentMasterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudDepartmentMasterDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudDepartmentMasterDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("GetDepartmentMasterDetails")]
        public IActionResult GetDepartmentMasterDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactDepartmentMasterDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetDepartmentMasterDetails), out _, skipTokenCheck: false));
        }
        [HttpPost("GetTrainMasterDetails")]
        public IActionResult GetTrainMasterDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactTrainMasterDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;

            }, nameof(GetTrainMasterDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("CrudTrainMasterDetails")]
        public IActionResult CrudTrainMasterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudTrainMasterDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudTrainMasterDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("GetTrainClassMasterDetails")]
        public IActionResult GetTrainClassMasterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                var (pSearch, _, _) = ApiHelper.GetSearchAndPagingObject(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pTotalCount, pWhere) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    includeTotalCount: true,
                    includeWhere: true

                );

                DataTable dt = _core.ExecProcDt("ReactTrainClassMasterDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);
                return outObj;
            }, nameof(GetTrainClassMasterDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("CrudTrainClassMasterDetails")]
        public IActionResult CrudTrainClassMasterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudTrainClassMasterDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudTrainClassMasterDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("GetLanguageMasterDetails")]
        public IActionResult GetLanguageMasterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                var (pSearch, _, _) = ApiHelper.GetSearchAndPagingObject(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pTotalCount, pWhere) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    includeTotalCount: true,
                    includeWhere: true

                );

                DataTable dt = _core.ExecProcDt("ReactLanguageMasterDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);
                return outObj;
            }, nameof(GetLanguageMasterDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("CrudLanguageMasterDetails")]
        public IActionResult CrudLanguageMasterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudLanguageMasterDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudLanguageMasterDetails), out _, skipTokenCheck: false));

        }


        [HttpPost("GetNewspaperMasterDetails")]
        public IActionResult GetNewspaperMasterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });

                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                var (pSearch, _, _) = ApiHelper.GetSearchAndPagingObject(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pTotalCount, pWhere) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    includeTotalCount: true,
                    includeWhere: true

                );

                DataTable dt = _core.ExecProcDt("ReactNewspaperMasterDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);
                return outObj;
            }, nameof(GetNewspaperMasterDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("CrudNewspaperMasterDetails")]
        public IActionResult CrudNewspaperMasterDetails([FromBody] object input)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );

                DataTable dt = _core.ExecProcDt("ReactCrudNewspaperMasterDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                return outObj;

            }, nameof(CrudNewspaperMasterDetails), out _, skipTokenCheck: false));

        }

        [HttpPost("CrudNewsfeedDetails")]
        public IActionResult CrudNewsfeedDetails([FromForm] string input, [FromForm] List<IFormFile> files)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(
                   string.IsNullOrEmpty(input) ? new { } : ApiHelper.ToObject(input) // deserialize JSON string

                );
                var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
                var filterKeys = ApiHelper.GetFilteredKeys(data);
                string pImagePath = string.Empty;
                string flag = data.ContainsKey("FLAG") ? data["FLAG"]?.ToString() ?? "" : "";
                if (flag == "SAVE")
                {
                    if (files == null || files.Count == 0)
                    {
                        outObj.StatusCode = 500;
                        outObj.Message = "File is required.";
                        outObj.LoginStatus = pJWT_LOGIN_NAME;
                        return outObj;
                    }
                    if (files.Count > 1)
                    {
                        outObj.StatusCode = 500;
                        outObj.Message = "Only one file can be uploaded.";
                        outObj.LoginStatus = pJWT_LOGIN_NAME;
                        return outObj;
                    }
                }
                if (flag == "DELETE")
                {
                    string pQry = @"SELECT TOP 1 FILE_PATH FROM NEWS_FEED  WHERE MP_SEAT_ID = @MP_SEAT_ID AND NEWS_FEED_ID=@ID";
                    // Get old MEDIA_DATE from DB (before update)
                    pImagePath = Convert.ToString(
                         _core.ExecScalarText(
                              pQry,
                               new[] {
                               new SqlParameter("@MP_SEAT_ID", pJWT_MP_SEAT_ID),
                               new SqlParameter("@ID", data["NEWS_FEED_ID"]?.ToString())

                               }
                          )
                       );

                }

                // Step 2: Build SQL parameters (advanced dynamic approach)
                var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    userId: pJWT_USERID,
                    includeRetId: true
                );
                DataTable dt = _core.ExecProcDt("ReactCrudNewsfeedDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                if (outObj.StatusCode == 200)
                {
                    if (flag == "SAVE" || flag == "UPDATE")
                    {
                        if (files.Count > 1)
                        {
                            outObj.StatusCode = 500;
                            outObj.Message = "You can upload a maximum of One file.";
                            outObj.LoginStatus = pJWT_LOGIN_NAME;
                            return outObj;
                        }
                        if (files != null && files.Count == 1)
                        {
                            var file = files.First();
                            string ext = Path.GetExtension(file.FileName).ToLower();
                            // ✅ Get file size in bytes
                            long fileSizeInBytes = file.Length;

                            // ✅ (Optional) Convert to KB or MB
                            double fileSizeInKB = fileSizeInBytes / 1024.0;
                            double fileSizeInMB = fileSizeInKB / 1024.0;
                            // ✅ Example: limit to 5 MB max
                            if (fileSizeInMB > 100)
                            {
                                outObj.StatusCode = 400;
                                outObj.Message = "File size exceeds the 100 MB limit.";
                                outObj.LoginStatus = pJWT_LOGIN_NAME;
                                return outObj;
                            }


                            string storageRoot = _settings.BasePath;
                            string baseFolder = Path.Combine("image", $"MP_{pJWT_MP_SEAT_ID}", "NewsFeedGallery");
                            string finalFolder = Path.Combine(storageRoot, baseFolder);
                            if (!Directory.Exists(finalFolder))
                            {
                                Directory.CreateDirectory(finalFolder);
                            }
                            string fileName = $"NewsFeed_{outObj.RetID}{ext}";
                            string relativePath = Path.Combine(baseFolder, fileName).Replace("\\", "/");
                            string fullPath = Path.Combine(finalFolder, fileName);
                            // ✅ If file already exists, delete it before saving
                            if (System.IO.File.Exists(fullPath))
                            {
                                System.IO.File.Delete(fullPath);
                            }
                            using (var stream = new FileStream(fullPath, FileMode.Create))
                            {
                                file.CopyTo(stream);
                            }

                            string updateQry = $"UPDATE NEWS_FEED SET NEWS_ATTACHMENTS = '" + fileName + "', FILE_PATH = '" + relativePath + "',NEWS_FILESIZE='" + fileSizeInKB + "' WHERE MP_SEAT_ID='" + pJWT_MP_SEAT_ID + "' AND NEWS_FEED_ID='" + outObj.RetID + "' ";
                            _core.ExecNonQuery(updateQry);
                        }
                    }
                    if (flag == "DELETE" && !string.IsNullOrEmpty(pImagePath))
                    {
                        string baseFolderPath = _settings.BasePath;
                        string fullFilePath = Path.Combine(baseFolderPath, pImagePath.Replace("/", "\\"));

                        if (System.IO.File.Exists(fullFilePath))
                        {
                            System.IO.File.Delete(fullFilePath);

                            string parentFolder = Path.GetDirectoryName(fullFilePath);
                            if (!string.IsNullOrEmpty(parentFolder) &&
                                Directory.Exists(parentFolder) &&
                                !Directory.EnumerateFileSystemEntries(parentFolder).Any())
                            {
                                Directory.Delete(parentFolder, true);
                            }
                        }

                    }

                }

                return outObj;
            }, nameof(CrudNewsfeedDetails), out _, skipTokenCheck: false));
        }

        [HttpPost("GetNewsFeedDetails")]
        public IActionResult GetNewsFeedDetails([FromBody] object input)
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

                DataTable dt = _core.ExecProcDt("ReactNewsFeedDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ✅ Apply pagination only if both values are set
                if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
                {
                    PaginationHelper.ApplyPagination(outObj, pTotalCount.Value?.ToString(), pageIndex.Value, pageSize.Value);
                }

                return outObj;
            }, nameof(GetNewsFeedDetails), out _, skipTokenCheck: false));
        }

    }
}
