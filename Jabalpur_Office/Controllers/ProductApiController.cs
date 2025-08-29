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
        [Route("CrudConstructionWorkDetails_Single")]
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
        [HttpPost]
        [Route("CrudConstructionWorkDetails")]
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

                if (outObj.StatusCode == 200 &&  (data["STAGES_MAS_ID"]?.ToString() =="7" || data["STAGES_MAS_ID"]?.ToString() == "9"))
                {
                    // Step 1: Validate & handle file uploads
                    if (files != null && files.Count > 0)
                    {
                        // Add FLAG to indicate existing record
                        // You can set the flag value depending on your logic, e.g., "EXISTS" or true/false
                        data["FLAG"] = "SAVE";
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
        [HttpPost]
        [Route("CrudConstructionImages")]
        public IActionResult CrudConstructionImages([FromForm] string input, [FromForm] List<IFormFile> files)
        {
            return Ok(ExecuteWithHandling(() =>
            {
                var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(
                  string.IsNullOrEmpty(input) ? new { } : ApiHelper.ToObject(input) // deserialize JSON string

                );

                var allowedKeys = new[] { "CW_CODE", "STAGES_MAS_ID","DOC_MAS_ID","FLAG" };

                var data = ApiHelper.ToObjectDictionary(rawData);

                var selectedData = data
                            .Where(kvp => allowedKeys.Contains(kvp.Key))
                            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);


                var filterKeys = ApiHelper.GetFilteredKeys(selectedData);

                string pFLAG = string.Empty;
                if (selectedData.ContainsKey("FLAG"))
                {
                    pFLAG = selectedData["FLAG"]?.ToString();
                }

                if (files != null && files.Count > 0 && pFLAG=="SAVE")
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
                                string baseFolder = $"image/MP_{pJWT_MP_SEAT_ID}/Construction/{cwCodeValue}";
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
                                string relativePath = $"image/MP_{pJWT_MP_SEAT_ID}/Construction/{cwCodeValue}/{FileName}";



                                string vQryUpdateStatus = $"UPDATE CONSTRUCTION_DOCUMENT_MASTER SET FILE_NAME='"+FileName+"' ,FILE_PATH='"+ relativePath + "' WHERE MP_SEAT_ID='"+ pJWT_MP_SEAT_ID + "' AND DOC_MAS_ID='"+ outObj.RetID + "' ";
                                _core.ExecNonQuery(vQryUpdateStatus);
                            }
                        }


                    }

                }
                if (pFLAG == "DELETE")
                {
                    try
                    {
                        // ✅ Step 1: Fetch the file details from DB using DOC_MAS_ID
                        string fetchQry = $@"
                           SELECT FILE_NAME, FILE_PATH,CW_CODE,  
                           FROM CONSTRUCTION_DOCUMENT_MASTER 
                           WHERE MP_SEAT_ID = '{pJWT_MP_SEAT_ID}' 
                           AND DOC_MAS_ID = '{selectedData["DOC_MAS_ID"]}' 
                           AND CW_CODE ='{selectedData["CW_CODE"]}'";
                        DataTable dtFile = _core.ExecProcDt(fetchQry, null);
                        if (dtFile.Rows.Count > 0)
                        {
                            string fileName = dtFile.Rows[0]["FILE_NAME"]?.ToString();
                            string filePath = dtFile.Rows[0]["FILE_PATH"]?.ToString();
                            string cwCode = dtFile.Rows[0]["CW_CODE"]?.ToString();

                            // ✅ Step 2: Delete file from server if exists
                            if (!string.IsNullOrEmpty(filePath) && System.IO.File.Exists(filePath))
                            {
                                System.IO.File.Delete(filePath);
                            }

                            // ✅ Step 3: Delete record from DB
                            string deleteQry = $@"
                              DELETE FROM CONSTRUCTION_DOCUMENT_MASTER
                              WHERE MP_SEAT_ID = '{pJWT_MP_SEAT_ID}' 
                              AND DOC_MAS_ID = '{selectedData["DOC_MAS_ID"]}'";
                            _core.ExecProcNonQuery(deleteQry, null);

                            // ✅ Step 4: Check if folder is empty → remove it
                            if (!string.IsNullOrEmpty(cwCode))
                            {
                                string folderPath = Path.Combine(_settings.BasePath, $"image/MP_{pJWT_MP_SEAT_ID}/Construction/{cwCode}");

                                if (Directory.Exists(folderPath) && !Directory.EnumerateFileSystemEntries(folderPath).Any())
                                {
                                    Directory.Delete(folderPath, true); // true = recursive delete if empty
                                }
                            }

                            outObj.StatusCode = 200;
                            outObj.Message = "File deleted successfully.";
                            outObj.LoginStatus = pJWT_LOGIN_NAME;
                        }

                    }
                    catch (Exception Ex)
                    {
                        outObj.StatusCode = 500;
                        outObj.LoginStatus = pJWT_LOGIN_NAME;
                        outObj.Message = "Error while deleting file: " + Ex.Message;
                    }
                }
                
                return outObj;

            }, nameof(CrudConstructionImages), out _, skipTokenCheck: false));


        }

        //11
        [HttpPost]
        [Route("GetConstructionDocumentMasterDetails")]
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
        [HttpPost]
        [Route("CrudConstructionFormFieldDetails")]
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
        [HttpPost]
        [Route("GetConstructionFormFieldMasterDetails")]
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
        [HttpPost]
        [Route("GetInspectionProgessStatusDetails")]
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

        [HttpPost]
        [Route("CrudConstructionInspectionDetails")]
        public IActionResult CrudConstructionInspectionDetails([FromForm] string input, [FromForm] List<IFormFile> files)
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

                DataTable dt = _core.ExecProcDt("ReactCrudConstructionInspectionDetails", paramList.ToArray());
                SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                if (outObj.StatusCode == 200 && files != null && files.Count > 0)
                {
                    data["FLAG"] = "SAVE";
                    data["MODULE_NM"] = "CONSTRUCTION_INSPECTION";
                    data["REFERENCE_ID"] = outObj.RetID;

                    // Convert updated dictionary back to JSON string for CrudConstructionImages
                    string updatedInput = JsonConvert.SerializeObject(data);
                    // Directly call the other method internally
                    var imagesResult = CrudConstructionInspectionImages(updatedInput, files) as ObjectResult;

                    // Merge status/message if needed
                    if (imagesResult?.Value is WrapperCrudObjectData imgOut)
                    {
                        outObj.Message += " | " + imgOut.Message;
                    }
                }
                return outObj;

            }, nameof(CrudConstructionInspectionDetails), out _, skipTokenCheck: false));


        }

        [HttpPost]
        [Route("CrudConstructionInspectionImages")]
        public IActionResult CrudConstructionInspectionImages([FromForm] string input, [FromForm] List<IFormFile> files)
        {
            return Ok(ExecuteWithHandling(() => {

                var (outObj, rawData) = PrepareWrapperAndData<WrapperCrudObjectData>(
                 string.IsNullOrEmpty(input) ? new { } : ApiHelper.ToObject(input) // deserialize JSON string
                );

                var allowedKeys = new[] { "CW_CODE", "MODULE_NM", "REFERENCE_ID", "FLAG", "ID" };

                var data = ApiHelper.ToObjectDictionary(rawData);

                var selectedData = data
                            .Where(kvp => allowedKeys.Contains(kvp.Key))
                            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);


                var filterKeys = ApiHelper.GetFilteredKeys(selectedData);

                string pFLAG = string.Empty;
                if (selectedData.ContainsKey("FLAG"))
                {
                    pFLAG = selectedData["FLAG"]?.ToString();
                }
                if (pFLAG == "SAVE")
                {
                    // ✅ Max 2 files
                    if (files.Count > 2)
                    {
                        outObj.StatusCode = 500;
                        outObj.Message = "You can upload a maximum of 2 files.";
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
                        }
                        // Step 2: Build SQL parameters (advanced dynamic approach)
                        var (paramList, pStatus, pMsg, pRetId) = SqlParamBuilderWithAdvancedCrud.BuildAdvanced(
                            data: selectedData,
                            keys: filterKeys,
                            mpSeatId: pJWT_MP_SEAT_ID,
                            userId: pJWT_USERID,
                            includeRetId: true
                        );

                        DataTable dt = _core.ExecProcDt("ReactCrudConstructionInspectionImages", paramList.ToArray());
                        SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);
                        if (outObj.StatusCode == 200 )
                        {
                            if (pFLAG == "SAVE")
                            {
                                var storageRoot = _settings.BasePath;
                            }
                        }
                    }
                }


                return outObj;
            }, nameof(CrudConstructionInspectionImages), out _, skipTokenCheck: false));
        }

        [HttpPost]
        [Route("GetConstructionInspectionDetails")]
        public IActionResult GetConstructionInspectionDetails([FromBody] object input)
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


    }
}
