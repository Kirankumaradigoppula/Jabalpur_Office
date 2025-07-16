using System.Data;
using System.Text.Json;
using Jabalpur_Office.Data;
using Jabalpur_Office.Helpers;
using Jabalpur_Office.Models;
using Jabalpur_Office.ServiceCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace Jabalpur_Office.Controllers
{
    public class BaseApiController : ControllerBase
    {
        protected string pJWT_LOGIN_NAME =>
            User?.Identity?.IsAuthenticated == true ? GetClaimValue("userName") : string.Empty;

        protected string pJWT_MP_SEAT_ID =>
            User?.Identity?.IsAuthenticated == true ? GetClaimValue("MP_SEAT_ID") : string.Empty;

        protected string pJWT_USERID =>
            User?.Identity?.IsAuthenticated == true ? GetClaimValue("USERID") : string.Empty;

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
                baseOutObj.Message = "An unexpected server error occurred: " + GetSafeErrorMessage(ex);
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
                LoginStatus = pJWT_LOGIN_NAME // From BaseApiController or token claims
            };

            try
            {
                // If not anonymous and token invalid → block
                bool isAnonymous = skipTokenCheck || IsCallerAnonymous();
                if (!isAnonymous && !CheckToken(out var loginResponse))
                {
                    return Unauthorized(loginResponse); // 401
                }

                var result = await func();
                return Ok(result); // 200
            }
            catch (SqlException ex)
            {
                LogError(ex, logContext + "_SQL");
                baseOutObj.StatusCode = 503;
                baseOutObj.Message = "Network failure: " + GetSafeErrorMessage(ex);
                return StatusCode(503, baseOutObj); // 503
            }
            catch (TimeoutException ex)
            {
                LogError(ex, logContext + "_TIMEOUT");
                baseOutObj.StatusCode = 504;
                baseOutObj.Message = "Request timed out. Please try again later.";
                return StatusCode(504, baseOutObj); // 504
            }
            catch (TaskCanceledException ex)
            {
                LogError(ex, logContext + "_TASK_CANCEL");
                baseOutObj.StatusCode = 408;
                baseOutObj.Message = "Request was cancelled or timed out.";
                return StatusCode(408, baseOutObj); // 408
            }
            catch (InvalidOperationException ex)
            {
                LogError(ex, logContext + "_INVALID_OP");
                baseOutObj.StatusCode = 409;
                baseOutObj.Message = "Invalid operation: " + GetSafeErrorMessage(ex);
                return Conflict(baseOutObj); // 409
            }
            catch (UnauthorizedAccessException ex)
            {
                LogError(ex, logContext + "_UNAUTHORIZED");
                baseOutObj.StatusCode = 401;
                baseOutObj.Message = "Access denied: " + GetSafeErrorMessage(ex);
                return Unauthorized(baseOutObj); // 401
            }
            catch (Exception ex)
            {
                LogError(ex, logContext + "_GENERAL");
                baseOutObj.StatusCode = 500;
                baseOutObj.Message = "An unexpected server error occurred: " + GetSafeErrorMessage(ex);
                return StatusCode(500, baseOutObj); // 500
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

        private readonly IsssCore _core;
        private AppDbContext context;

        public BaseApiController(IsssCore core)
        {
            _core = core;
        }

        public BaseApiController(AppDbContext context)
        {
            this.context = context;
        }

        protected List<Dictionary<string, string>> ToDictionaryList(DataTable dt)
        {
            return ApiHelper.ConvertToDictionaryList(dt);
        }

        protected void SetOutput(SqlParameter status, SqlParameter message, Product response)
        {
            ApiHelper.SetOutputParams(status, message, response);
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

        private Dictionary<string, string> ConvertToDictionary(object input)
        {
            if (input == null)
                return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            // Serialize to JSON, then deserialize to Dictionary
            var json = JsonSerializer.Serialize(input);
            return JsonSerializer.Deserialize<Dictionary<string, string>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? new Dictionary<string, string>();
        }

        protected void LogError(Exception ex, string location)
        {
            try
            {
                List<SqlParameter> logParams = new List<SqlParameter>
                {
                    new SqlParameter("@pMP_SEAT_ID", pJWT_MP_SEAT_ID ?? ""),
                    new SqlParameter("@pAPI_NAME", location),
                    new SqlParameter("@pERRORMESSAGE", ex.Message),
                    new SqlParameter("@pSTACKTRACE", ex.StackTrace ?? ""),
                    new SqlParameter("@pEUSER", pJWT_USERID ?? "")
                };

                _core.ExecProcDt("InsertApiErrorLog", logParams.ToArray()); // Assuming this SP exists
            }
            catch (Exception loggingEx)
            {
                Console.WriteLine($"Logging failed: {loggingEx.Message}");
            }
        }



    }
}
