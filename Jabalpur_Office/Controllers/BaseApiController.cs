using System.Data;
using System.Text.Json;
using Jabalpur_Office.Data;
using Jabalpur_Office.Filters;
using Jabalpur_Office.Helpers;
using Jabalpur_Office.Models;
using Jabalpur_Office.ServiceCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using static Jabalpur_Office.Helpers.ApiHelper;
using static Jabalpur_Office.Filters.JwtTokenHelper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Jabalpur_Office.Controllers
{
    [Authorize] // 🔹 Applies globally to all controllers inheriting from this
    [ApiController]
    public class BaseApiController : ControllerBase
    {
        protected string pJWT_LOGIN_NAME =>
            User?.Identity?.IsAuthenticated == true ? GetClaimValue("userName") : string.Empty;

        protected string pJWT_MP_SEAT_ID =>
            User?.Identity?.IsAuthenticated == true ? GetClaimValue("MP_SEAT_ID") : string.Empty;

        protected string pJWT_USERID =>
            User?.Identity?.IsAuthenticated == true ? GetClaimValue("USERID") : string.Empty;
       
       

        private readonly AppDbContext _context;
        private readonly IsssCore __core;

        private readonly JwtTokenHelper _jwtTokenHelper;

        private readonly StorageSettings _settings;

        private readonly IHttpContextAccessor _httpContextAccessor;

        public BaseApiController(AppDbContext context, IsssCore core_, JwtTokenHelper jwtToken, IOptions<StorageSettings> settings, IHttpContextAccessor httpContextAccessor) 
        {
            _context = context;
            __core = core_;
            _jwtTokenHelper = jwtToken;
            _settings = settings.Value;
            _httpContextAccessor = httpContextAccessor;

        }



        protected string GetClaimValue(string key)
        {
            return User?.FindFirst(key)?.Value ?? string.Empty;
        }

        protected bool CheckToken(out Product response)
        {
            response = new Product();
            if (string.IsNullOrWhiteSpace(pJWT_LOGIN_NAME))
            {
                response.StatusCode = 401;
                response.Message = "Unauthorized: Missing or invalid token.";
                return false;
            }
            return ApiHelper.IsTokenValid(pJWT_LOGIN_NAME, out response);
        }

        protected TResult ExecuteWithHandling<TResult>(
          Func<TResult> func,
          string logContext,
          out Product baseOutObj,
          bool skipTokenCheck = false)
          where TResult : Product, new()
        {
            baseOutObj = new TResult
            {
                LoginStatus = pJWT_LOGIN_NAME // From BaseApiController
            };

            // If not anonymous and token invalid → block
            bool isAnonymous = skipTokenCheck || IsCallerAnonymous();
            if (!isAnonymous && !CheckToken(out var loginResponse))
            {
                return loginResponse as TResult;
            }

            try
            {
                return func();
            }
            catch (HttpRequestException ex)
            {
                LogError(ex, logContext + "_SQL");
                baseOutObj.StatusCode = 503;
                baseOutObj.Message = "Network error: " + GetSafeErrorMessage(ex);
            }
            catch (SqlException ex)
            {
                LogError(ex, logContext + "_SQL");
                baseOutObj.StatusCode = 503;
                baseOutObj.Message = "Network failure: " + GetSafeErrorMessage(ex);
            }
            catch (TimeoutException ex)
            {
                LogError(ex, logContext + "_TIMEOUT");
                baseOutObj.StatusCode = 504;
                baseOutObj.Message = "Request timed out. Please try again later.";
            }
            catch (TaskCanceledException ex)
            {
                LogError(ex, logContext + "_TASK_CANCEL");
                baseOutObj.StatusCode = 408;
                baseOutObj.Message = "Request was cancelled or timed out.";
            }
            catch (InvalidOperationException ex)
            {
                LogError(ex, logContext + "_INVALID_OP");
                baseOutObj.StatusCode = 409;
                baseOutObj.Message = "Invalid operation: " + GetSafeErrorMessage(ex);
            }
            catch (UnauthorizedAccessException ex)
            {
                LogError(ex, logContext + "_UNAUTHORIZED");
                baseOutObj.StatusCode = 401;
                baseOutObj.Message = "Access denied: " + GetSafeErrorMessage(ex);
            }
            catch (Exception ex)
            {
                LogError(ex, logContext + "_GENERAL");
                baseOutObj.StatusCode = 500;
                baseOutObj.Message = "An unexpected server error occurred: " + ex.Message.ToString();
            }

            return baseOutObj as TResult;
        }

        protected async Task<IActionResult> ExecuteWithHandlingAsync<TResult>(
         Func<Task<TResult>> func,
         string logContext,
         bool skipTokenCheck = false)
         where TResult : Product, new()
        {
            var baseOutObj = new TResult
            {
                LoginStatus = pJWT_LOGIN_NAME
            };

            try
            {
                bool isAnonymous = skipTokenCheck || IsCallerAnonymous();
                if (!isAnonymous && !CheckToken(out var loginResponse))
                    return Unauthorized(loginResponse);

                var result = await func();
                return Ok(result);
            }
            catch (SqlException ex)
            {
                LogError(ex, logContext + "_SQL");
                baseOutObj.StatusCode = 503;
                baseOutObj.Message = "Network failure: " + GetSafeErrorMessage(ex);
                return StatusCode(503, baseOutObj);
            }
            catch (TimeoutException ex)
            {
                LogError(ex, logContext + "_TIMEOUT");
                baseOutObj.StatusCode = 504;
                baseOutObj.Message = "Request timed out. Please try again later.";
                return StatusCode(504, baseOutObj);
            }
            catch (TaskCanceledException ex)
            {
                LogError(ex, logContext + "_TASK_CANCEL");
                baseOutObj.StatusCode = 408;
                baseOutObj.Message = "Request was cancelled or timed out.";
                return StatusCode(408, baseOutObj);
            }
            catch (InvalidOperationException ex)
            {
                LogError(ex, logContext + "_INVALID_OP");
                baseOutObj.StatusCode = 409;
                baseOutObj.Message = "Invalid operation: " + GetSafeErrorMessage(ex);
                return Conflict(baseOutObj);
            }
            catch (UnauthorizedAccessException ex)
            {
                LogError(ex, logContext + "_UNAUTHORIZED");
                baseOutObj.StatusCode = 401;
                baseOutObj.Message = "Access denied: " + GetSafeErrorMessage(ex);
                return Unauthorized(baseOutObj);
            }
            catch (Exception ex)
            {
                LogError(ex, logContext + "_GENERAL");
                baseOutObj.StatusCode = 500;
                baseOutObj.Message = "An unexpected server error occurred: " + GetSafeErrorMessage(ex);
                return StatusCode(500, baseOutObj);
            }
        }
        protected async Task<IActionResult> ExecuteWithHandlingAsync(
          Func<Task<IActionResult>> func,
          string logContext,
          bool skipTokenCheck = false)
        {
            try
            {
                bool isAnonymous = skipTokenCheck || IsCallerAnonymous();
                if (!isAnonymous && !CheckToken(out var loginResponse))
                    return Unauthorized(loginResponse);

                return await func();
            }
            catch (SqlException ex)
            {
                LogError(ex, logContext + "_SQL");
                return StatusCode(503, new
                {
                    Status = "FAIL",
                    Message = "Network failure: " + GetSafeErrorMessage(ex)
                });
            }
            catch (TimeoutException ex)
            {
                LogError(ex, logContext + "_TIMEOUT");
                return StatusCode(504, new
                {
                    Status = "FAIL",
                    Message = "Request timed out."
                });
            }
            catch (TaskCanceledException ex)
            {
                LogError(ex, logContext + "_TASK_CANCEL");
                return StatusCode(408, new
                {
                    Status = "FAIL",
                    Message = "Request was cancelled or timed out."
                });
            }
            catch (InvalidOperationException ex)
            {
                LogError(ex, logContext + "_INVALID_OP");
                return Conflict(new
                {
                    Status = "FAIL",
                    Message = "Invalid operation: " + GetSafeErrorMessage(ex)
                });
            }
            catch (UnauthorizedAccessException ex)
            {
                LogError(ex, logContext + "_UNAUTHORIZED");
                return Unauthorized(new
                {
                    Status = "FAIL",
                    Message = "Access denied: " + GetSafeErrorMessage(ex)
                });
            }
            catch (Exception ex)
            {
                LogError(ex, logContext + "_GENERAL");
                return StatusCode(500, new
                {
                    Status = "FAIL",
                    Message = "Unexpected error: " + GetSafeErrorMessage(ex)
                });
            }
        }

       

        //Zip File
        protected IActionResult ExecuteWithHandlingFile(
            Func<(byte[] fileBytes, string contentType, string fileName, Product outObj)> func,
            string logContext,
            out Product baseOutObj,
            bool skipTokenCheck = false)
        {
            baseOutObj = new Product();

            bool isAnonymous = skipTokenCheck || IsCallerAnonymous();
            if (!isAnonymous && !CheckToken(out var loginResponse))
            {
                return Unauthorized(new
                {
                    StatusCode = 401,
                    Message = "Unauthorized or invalid token."
                });
            }

            try
            {
                var (fileBytes, contentType, fileName, outObj) = func();
                baseOutObj = outObj ?? new Product();

                // ✅ If outObj.StatusCode != 200 or fileBytes is null → return JSON
                if (outObj == null || outObj.StatusCode != 200 || fileBytes == null || fileBytes.Length == 0)
                {
                    return StatusCode(outObj.StatusCode != 0 ? outObj.StatusCode : 500, outObj);
                }

                // ✅ Success → return downloadable file
                return File(fileBytes, contentType, fileName);
            }
            catch (HttpRequestException ex)
            {
                LogError(ex, logContext + "_HTTP");
                return StatusCode(503, new { Message = "Network error: " + GetSafeErrorMessage(ex) });
            }
            catch (SqlException ex)
            {
                LogError(ex, logContext + "_SQL");
                return StatusCode(500, new { Message = "Database error: " + GetSafeErrorMessage(ex) });
            }
            catch (UnauthorizedAccessException ex)
            {
                LogError(ex, logContext + "_UNAUTHORIZED");
                return StatusCode(401, new { Message = "Access denied: " + GetSafeErrorMessage(ex) });
            }
            catch (Exception ex)
            {
                LogError(ex, logContext + "_GENERAL");
                return StatusCode(500, new { Message = "Unexpected error: " + GetSafeErrorMessage(ex) });
            }
        }


        private bool IsCallerAnonymous()
        {
            try
            {
                // Access current HTTP context
                var endpoint = HttpContext?.GetEndpoint();

                if (endpoint == null)
                    return false;

                // Check if the endpoint allows anonymous access
                var allowAnonymous = endpoint.Metadata.GetMetadata<Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute>();

                return allowAnonymous != null;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Returns a safe, truncated version of the exception message (max 300 characters).
        /// </summary>
        public static string GetSafeErrorMessage(Exception ex)
        {
            if (ex == null)
                return "An unknown error occurred.";

            string message = ex.Message ?? "No error message provided.";

            return message.Length > 300 ? message.Substring(0, 300) + "..." : message;
        }

        
        protected List<Dictionary<string, string>> ToDictionaryList(DataTable dt)
        {
            return ApiHelper.ConvertToDictionaryList(dt);
        }

        protected void SetOutput(SqlParameter status, SqlParameter message, Product response)
        {
            ApiHelper.SetOutputParams(status, message, response);
        }

       
        protected void SetOutputWithRetId(SqlParameter status, SqlParameter message,SqlParameter RetID, Product response)
        {
            ApiHelper.SetOutputParamsWithRetId(status, message, RetID, response);
        }
      

        protected (TWrapper wrapper, Dictionary<string, string> data) PrepareWrapperAndData<TWrapper>(object input)
    where TWrapper : Product, new()
        {
            var wrapper = new TWrapper
            {
                LoginStatus = pJWT_LOGIN_NAME
            };

            // Convert input object to Dictionary<string, string>
            var data = ConvertToDictionary(input);

            return (wrapper, data);
        }

        //For Crud Operations
        protected (TWrapper wrapper, Dictionary<string, object> parameters)
           PrepareCrudRequest<TWrapper>(object input, string loginName)
           where TWrapper : WrapperCrudObjectData, new()
        {
            // 1. Initialize wrapper
            var wrapper = new TWrapper
            {
                LoginStatus = loginName
            };

            // 2. Convert input object → Dictionary<string, object>
            var parameters = input != null
                ? input.GetType().GetProperties()
                      .ToDictionary(
                          prop => prop.Name,
                          prop => prop.GetValue(input, null) ?? DBNull.Value)
                : new Dictionary<string, object>();

            return (wrapper, parameters);
        }

        private Dictionary<string, string> ConvertToDictionary(object input)
        {
            if (input == null)
                return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            //// Serialize to JSON, then deserialize to Dictionary
            var json = JsonSerializer.Serialize(input);
            return JsonSerializer.Deserialize<Dictionary<string, string>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? new Dictionary<string, string>();

            // Deserialize to Dictionary<string, object> first
            //var json = JsonSerializer.Serialize(input);
            //var dict = JsonSerializer.Deserialize<Dictionary<string, object>>(json,
            //    new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            //    ?? new Dictionary<string, object>();

            //// Convert all values to string
            //return dict.ToDictionary(
            //    kvp => kvp.Key,
            //    kvp => kvp.Value?.ToString() ?? string.Empty,
            //    StringComparer.OrdinalIgnoreCase
            //);
        }


        protected void LogError(Exception ex, string location)
        {
            try
            {
                if (ex == null) ex = new Exception("Unknown exception (null)");

                string fullError = ex.ToString();

                var logParams = new List<SqlParameter>
                {
                    new SqlParameter("@pMP_SEAT_ID", string.IsNullOrEmpty(pJWT_MP_SEAT_ID?.ToString())
                                                      ? (object)DBNull.Value
                                                      : pJWT_MP_SEAT_ID),
                    new SqlParameter("@pAPI_NAME", string.IsNullOrEmpty(location) ? "Unknown" : location),
                    new SqlParameter("@pERRORMESSAGE", string.IsNullOrEmpty(ex.Message) ? "No message" : ex.Message),
                    new SqlParameter("@pSTACKTRACE", fullError ?? ""),
                    new SqlParameter("@pEUSER", string.IsNullOrEmpty(pJWT_USERID?.ToString())
                                                ? (object)DBNull.Value
                                                : pJWT_USERID)
                };

                if (__core != null) // ✅ avoid null reference on _core
                {
                    __core.ExecProcDt("InsertApiErrorLog", logParams.ToArray());
                }
                else
                {
                    Console.WriteLine("⚠️ _core is NULL, cannot log to DB.");
                }
            }
            catch (Exception loggingEx)
            {
                Console.WriteLine($"Logging failed: {loggingEx}");
            }
        }

        protected WrapperListData ExecuteUniversalList(
           object input,
           string procName,
           List<OutParamSpec>? outParamsSpec = null,  // 👈 fully dynamic OUT params
           string? apiflag = null
        )
        {
            // 1. Prepare wrapper & raw data
            var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });


            // 2. Convert to object dictionary
            var data = ApiHelper.ToObjectDictionary(rawData);
            if (apiflag == "APPEND_DETAILS_VISITOR" || apiflag == "API_WEB_PORTAL" || apiflag == "USER_DETAILS")
            {
                data["USERID"] = pJWT_USERID;
            }
            var filterKeys = ApiHelper.GetFilteredKeys(data);

            // 3. Extract search & paging
            var (pSearch, pageIndex, pageSize) = ApiHelper.GetSearchAndPagingObject(data);




            // 4. Build SQL parameters
            var (paramList, pStatus, pMsg, pTotalCount, pWhere) =
                SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    includeTotalCount: true,
                    includeWhere: true,
                    pageIndex: pageIndex,
                    pageSize: pageSize
                );

            // 5. Add DYNAMIC OUT PARAMS
            Dictionary<string, SqlParameter> outParams = new();
            if (outParamsSpec != null)
            {
                foreach (var spec in outParamsSpec)
                {
                    SqlParameter p =
                        ApiHelper.CreateDynamicOutParam("@p" + spec.Name, spec.Type, spec.Size);

                    paramList.Add(p);

                    outParams[spec.Name] = p;
                }
            }

            // 6. Execute stored procedure
            //DataTable dt = _core.ExecProcDt(procName, paramList.ToArray());
            DataSet ds = __core.ExecProcDs(procName, paramList.ToArray());
            DataTable dt = (ds != null && ds.Tables.Count > 0) ? ds.Tables[0] : new DataTable();
            // 7. Convert to output wrapper
            ApiHelper.SetDataTableListOutput(dt, outObj);

            // 8. Set output message + status
            SetOutput(pStatus, pMsg, outObj);




            // 9. Apply pagination
            if (pTotalCount != null && pageIndex.HasValue && pageSize.HasValue)
            {
                PaginationHelper.ApplyPagination(
                    outObj,
                    pTotalCount.Value?.ToString(),
                    pageIndex.Value,
                    pageSize.Value
                );
            }

            // 10. Add OUT parameters to ExtraData
            foreach (var item in outParams)
            {
                var key = item.Key;
                var val = item.Value.Value;

                outObj.ExtraData[key] =
                    val == DBNull.Value ? null : val;
            }

            if (ds.Tables.Count > 1 && ds.Tables[1] != null && ds.Tables[1].Rows.Count > 0)
            {
                outObj.ExtraData["COLUMN_LIST"] =
                   ds.Tables[1].Rows[0]["COLUMN_JSON"]?.ToString() ?? "[]";
            }
            return outObj;
        }

        protected WrapperListData ExecuteUniversalCrudWithRetId(
            object input,
            string procName,
            List<OutParamSpec>? outParamsSpec = null, // 👈 fully dynamic OUT params
            string? apiflag = null
        )
        {
            var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
            var data = ApiHelper.ToObjectDictionary(rawData); // Dictionary<string, object>
            var filterKeys = ApiHelper.GetFilteredKeys(data);

            string flag = data.ContainsKey("FLAG") ? data["FLAG"]?.ToString() ?? "" : "";

            if (!string.IsNullOrEmpty(apiflag))
            {
                if (apiflag == "API_CRUD_APPOINTMENT")
                {
                    data["ENTRY_FROM"] = "PORTAL";
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

            // 5. Add DYNAMIC OUT PARAMS
            Dictionary<string, SqlParameter> outParams = new();
            if (outParamsSpec != null)
            {
                foreach (var spec in outParamsSpec)
                {
                    SqlParameter p =
                        ApiHelper.CreateDynamicOutParam("@p" + spec.Name, spec.Type, spec.Size);

                    paramList.Add(p);

                    outParams[spec.Name] = p;
                }
            }

            DataTable dt = __core.ExecProcDt(procName, paramList.ToArray());

            SetOutputParamsWithRetId(pStatus, pMsg, pRetId, outObj);

            string autoSmsStatus = string.Empty;

            foreach (var item in outParams)
            {

                var key = item.Key;
                var rawVal = item.Value?.Value;

                string? value =
                    rawVal == null || rawVal == DBNull.Value
                    ? string.Empty
                    : rawVal.ToString();

                // Store in ExtraData (existing logic)
                outObj.ExtraData[key] = value ?? string.Empty;

                // Capture specific OUT parameter
                if (key.Equals("AUTO_SMS_STATUS", StringComparison.OrdinalIgnoreCase))
                {
                    autoSmsStatus = value ?? "N";
                }


            }

            if (outObj.StatusCode != 200)
                return outObj;

            

            return outObj;
        }



    }
}
