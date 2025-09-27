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


    }
}
