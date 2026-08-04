using Jabalpur_Office.Models;
using Jabalpur_Office.ServiceCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Data.SqlClient;
using System.Data;
using System.Text.Json;

namespace Jabalpur_Office.Filters
{
    public class CheckMenuAccessAttribute : Attribute, IAsyncActionFilter
    {
        private readonly string _flagField;
        private readonly string _actionType; // C / U / D / VIEW

        public CheckMenuAccessAttribute(string actionType = "VIEW", string flagField = "Flag")
        {
            _flagField = flagField;
            _actionType = actionType.ToUpper();
        }

        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var httpContext = context.HttpContext;
            try
            {
                // =====================================================
                // ✅ Resolve Service
                // =====================================================
                var core = httpContext.RequestServices.GetService<IsssCore>();

                if (core == null)
                {
                    context.Result = new ObjectResult(new
                    {
                        statusCode = 400,
                        message = "Service resolution failed."
                    })
                    { StatusCode = 400 };

                    return;
                }

                // =====================================================
                // ✅ Get Claims
                // =====================================================

                string? userId = httpContext.User?.FindFirst("USERID")?.Value ?? httpContext.Items["USERID"]?.ToString();
                string? mpSeatId = httpContext.User?.FindFirst("MP_SEAT_ID")?.Value ?? httpContext.Items["MP_SEAT_ID"]?.ToString();
                string? userName = httpContext.User?.FindFirst("userName")?.Value ?? httpContext.Items["userName"]?.ToString();

                if (string.IsNullOrWhiteSpace(userId) ||
                    string.IsNullOrWhiteSpace(mpSeatId))
                {
                    context.Result = new UnauthorizedObjectResult(new
                    {
                        statusCode = 401,
                        message = "Invalid or expired token."
                    });

                    return;
                }

                //string? pagePath = context.HttpContext.Request.Headers["PagePath"].FirstOrDefault();
                string? pagePath = httpContext.Request.Headers["PagePath"].FirstOrDefault();
                //string? lastPath =  pagePath?.Split('/').LastOrDefault();
                string lastPath = string.Empty;

                if (!string.IsNullOrWhiteSpace(pagePath))
                {
                    lastPath = pagePath.Split('/',
                                StringSplitOptions.RemoveEmptyEntries)
                                .LastOrDefault() ?? "";
                }

                // =====================================================
                // ✅ Get API Name
                // =====================================================
                  var endpoint = context.ActionDescriptor as ControllerActionDescriptor;
                  
                  string apiName = endpoint?.ActionName ?? string.Empty;
                // =====================================================
                // ✅ Resolve Action Type
                // =====================================================

                string actionType = _actionType;

                if (_actionType.Equals("AUTO", StringComparison.OrdinalIgnoreCase))
                {
                    actionType = "VIEW";
                    try
                    {
                        if (context.ActionArguments.TryGetValue("input", out var inputObj))
                        {
                            string jsonString = inputObj?.ToString() ?? "";
                            if (!string.IsNullOrWhiteSpace(jsonString))
                            {
                                using JsonDocument json = JsonDocument.Parse(jsonString);
                                if (json.RootElement.TryGetProperty(
                                  "FLAG",
                                  out JsonElement flagElement))
                                {
                                    string flag = flagElement.GetString()?
                                                .Trim()
                                                .ToUpperInvariant() ?? "";

                                    actionType = flag switch
                                    {
                                        "SAVE" => "C",
                                        "SAVE_CATEGORY" => "C",
                                        "SAVE_DISPATCH_STATUS" => "C",
                                        "TRY" => "C",

                                        "UPDATE" => "U",
                                        "UPDATE_DESCRIPTION" => "U",
                                        "DOB_UPDATE" => "U",
                                        "DOA_UPDATE" => "U",
                                        "CHECK_NEGATIVE" => "U",
                                        "APPO_STATUS" => "U",
                                        "UPDATE_CATEGORY" => "U",
                                        "GOOGLE_DRAFT_LETTER" => "U",
                                        "SAVE_LETTER" => "U",
                                        "UPDATE_LETTER" => "U",
                                        "LIKED_LETTER" => "U",
                                        "TO_ATTEND" => "U",
                                        "UPDATE_OTP" => "U",
                                        "SWCCHAMAD_DETAILS" => "U",
                                        "U_TRY" => "U",
                                        "UPDATE_TRANSFER" => "U",
                                        "ATTENDED_STATUS" => "U",
                                        "UPDATE_VISIBLE_STATUS" => "U",
                                        

                                        "DELETE" => "D",
                                        "DELETE_IMAGE" => "D",
                                        "DOB_DELETE" => "D",
                                        "DOA_DELETE" => "D",
                                        "DELETE_CATEGORY" => "D",
                                        "DELETE_GOOGLE_DRAFT_LETTER" => "D",

                                        _ => "VIEW"
                                    };
                                }
                            }
                        }
                    }
                    catch { 
                       actionType = "VIEW";
                    }
                }

                // =====================================================
                // ✅ Database Parameters
                // =====================================================
                var param = new[]
                    {
                          new SqlParameter("@pUSERID", userId),
                          new SqlParameter("@pMP_SEAT_ID", mpSeatId),
                          new SqlParameter("@pAPI_NAME", apiName),
                          new SqlParameter("@pPATH", lastPath)
                    };

                // =====================================================
                // ✅ Execute Procedure
                // =====================================================
                DataTable dt = core.ExecProcDt("ReactCheckUserMenuPermission", param);
                if (dt == null || dt.Rows.Count == 0)
                {
                    context.Result = new ObjectResult(new
                    {
                        statusCode = 400,
                        message = "Permission details not found."
                    })
                    { StatusCode = 400 };

                    return;
                }

                var row = dt.Rows[0];

                // =====================================================
                // ✅ Safe Conversion
                // =====================================================

                int hasAccess = row["MENU_HAS_ACCESS"] != DBNull.Value ? Convert.ToInt32(row["MENU_HAS_ACCESS"]) : 0;
                int c = row["C_USER_ACCESS"] != DBNull.Value ? Convert.ToInt32(row["C_USER_ACCESS"]) : 0;
                int u = row["U_USER_ACCESS"] != DBNull.Value ? Convert.ToInt32(row["U_USER_ACCESS"]) : 0;
                int d = row["D_USER_ACCESS"] != DBNull.Value ? Convert.ToInt32(row["D_USER_ACCESS"]) : 0;
                int statusCode = row["statusCode"] != DBNull.Value ? Convert.ToInt32(row["statusCode"]) : 500;
                string message = row["Message"]?.ToString() ?? "";

                // =====================================================
                // ❌ DB Validation Failed
                // =====================================================
                  if (statusCode != 200)
                  {
                      context.Result = new ObjectResult(new
                      {
                          statusCode,
                          message
                      })
                      { StatusCode = statusCode };
                  
                      return;
                  }
                // =====================================================
                // ❌ Menu Access Check
                // =====================================================
                  if (hasAccess == 0)
                  {
                      context.Result = new ObjectResult(new WrapperListData
                      {
                          StatusCode = 400,
                          Message = "This user does not have permission to access this menu. Access to the menu has been denied.",
                          LoginStatus = userName ?? ""
                      })
                      { StatusCode = 400 };
                  
                      return;
                  }

                // =====================================================
                // ❌ CRUD Permission Check
                // =====================================================
                    bool isAllowed = actionType switch
                    {
                        "C" => c == 1,
                        "U" => u == 1,
                        "D" => d == 1,
                        "VIEW" => true,
                        _ => false
                    };
                    if (!isAllowed)
                    {
                        string permissionMessage = actionType switch
                        {
                            //"C" => "This user does not have permission to create a new record. Create access has been denied.",
                            // "D" => "This user does not have permission to delete the record. Delete access has been denied.",
                            "C" => "You do not have permission to create new records in this module.Please contact your super admin.",
                            "U" => "You do not have permission to edit records in this module. Please contact your super admin.",
                            "D" => "You do not have permission to delete records in this module. Please contact your super admin.",
                            _ => "Permission denied."
                        };
                    
                        context.Result = new ObjectResult(new WrapperListData
                        {
                            StatusCode = 403,
                            Message = permissionMessage,
                            //RetID = 0,
                            LoginStatus = userName ?? "",
                            ExtraData = []//new Dictionary<string, object?>()
                        })
                        {
                            StatusCode = 403
                        };
                    
                    
                    
                        return;
                    }

                // =====================================================
                // ✅ Continue Controller Execution
                // =====================================================
                    var executedContext = await next();
                // =====================================================
                // ✅ Get API Response (outObj)
                // =====================================================
                  if (executedContext.Result is OkObjectResult okResult)
                  {
                      // Full API response
                      var responseObject = okResult.Value;
                  
                      // =====================================================
                      // ✅ If Response Type Is WrapperListData
                      // =====================================================
                      if (responseObject is WrapperListData outObj)
                      {
                          // Example Access
                          string responseMessage = outObj.Message ?? "";
                          int responseStatus = outObj.StatusCode;
                          //int retId = outObj.RetID;
                          // Optional Logging
                          Console.WriteLine(
                              $"API Success : {responseMessage}");
                      }
                  }


            }
            catch (Exception ex)
            {
                context.Result = new ObjectResult(new
                {
                    statusCode = 400,//500
                    message = "Access validation failed.",
                    error = ex.Message
                })
                { StatusCode = 400 };
            }
        }

    }
}
