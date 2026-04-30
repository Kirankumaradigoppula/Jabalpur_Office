using ClosedXML.Excel;
using Jabalpur_Office.Data;
using Jabalpur_Office.Filters;
using Jabalpur_Office.Helpers;
using Jabalpur_Office.Models;
using Jabalpur_Office.ServiceCore;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using System.Data;
using System.IO.Compression;
using System.Net;
using static Jabalpur_Office.Helpers.ApiHelper;


namespace Jabalpur_Office.Controllers
{
    [EnableCors("AllowAll")] // ✅ Use named policy defined in Program.cs
    [Route("api/ZipController")]
    public class ZipController : BaseApiController
    {
        private readonly AppDbContext _context;
        private readonly IsssCore _core;

        private readonly JwtTokenHelper _jwtTokenHelper;

        private readonly IWebHostEnvironment _env;

        private readonly StorageSettings _settings;

        private readonly IExportService _exportService;

        private readonly IHttpContextAccessor _httpContextAccessor;
        public ZipController(AppDbContext context, IsssCore core, JwtTokenHelper jwtToken, IWebHostEnvironment env, IOptions<StorageSettings> settings, Jabalpur_Office.ServiceCore.IExportService exportService, IHttpContextAccessor httpContextAccessor) : base(context, core, jwtToken, settings, httpContextAccessor)
        {
            _context = context;
            _core = core;
            _jwtTokenHelper = jwtToken;
            _env = env;
            _settings = settings.Value;
            _exportService = exportService;
            _httpContextAccessor = httpContextAccessor;

        }


        [HttpPost("DownloadDetailsDataInZip")]

        public IActionResult DownloadDetailsDataInZip([FromBody] object input)
        {

            return ExecuteWithHandlingFile(() =>
            {
                // Step 1: Prepare wrapper and parameters
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


                var FOLDER_NAME = new SqlParameter("@pFOLDER_NAME", SqlDbType.Bit)
                {
                    Direction = ParameterDirection.Output
                };
                paramList.Add(FOLDER_NAME);

                // Step 2: Get data from DB
                DataTable dt = _core.ExecProcDt("ReactDownloadDetailsDataInZip", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                if (outObj.StatusCode != 200)
                {
                    //return (Array.Empty<byte>(), "application/json", "error.json", outObj);

                    outObj.StatusCode = outObj.StatusCode == 0 ? 500 : outObj.StatusCode;
                    outObj.Message = string.IsNullOrEmpty(outObj.Message)
                        ? "No data available or error occurred."
                        : outObj.Message;

                    // Instead of returning an empty file, return JSON
                    return (null, "application/json", "error.json", outObj);
                }


                string folderName = $"{pJWT_MP_SEAT_ID}_Data_{DateTime.Now:yyyyMMdd_HHmmss}";
                if (FOLDER_NAME.Value != DBNull.Value)
                {
                    folderName =Convert.ToString(FOLDER_NAME.Value);
                }


                // Step 3: Create Excel (excluding file path columns)
                string basePath = Path.Combine(Directory.GetCurrentDirectory(), _settings.BasePath, "image", $"MP_{pJWT_MP_SEAT_ID}", "Download", folderName);
                Directory.CreateDirectory(basePath);

                string excelFilePath = Path.Combine(basePath, $"{folderName}.xlsx");

                // Create a clean DataTable for Excel (exclude file/path columns)
                // 3️⃣ Remove file/path columns for Excel only
                DataTable dtForExcel = dt.Copy();
                var fileColumns = dt.Columns.Cast<DataColumn>() // ✅ FIX: use original dt, not dtForExcel
                    .Where(c => c.ColumnName.ToUpper().Contains("FILE_PATH") || c.ColumnName.ToUpper().Contains("FILE"))
                    .ToList();

                var excelColumnsToRemove = dtForExcel.Columns.Cast<DataColumn>()
                    .Where(c => c.ColumnName.ToUpper().Contains("FILE_PATH") || c.ColumnName.ToUpper().Contains("FILE"))
                    .ToList();

                foreach (var col in excelColumnsToRemove)
                    dtForExcel.Columns.Remove(col);

                // 4️⃣ Create Excel file
                using (var workbook = new XLWorkbook())
                {
                    var ws = workbook.Worksheets.Add("Event Details");
                    ws.Cell(1, 1).InsertTable(dtForExcel, "Events", true);
                    workbook.SaveAs(excelFilePath);
                }

                // Step 5: Create ZIP safely
                //byte[] zipBytes;
                string storageRoot = _settings.BasePath;//@"E:\CORE_PROJECTS\MpAttachedFiles"; //// main file storage path
                List<string> filePaths = new List<string>();
                foreach (DataRow row in dt.Rows)
                {
                    foreach (var col in fileColumns)
                    {
                        string rel = Convert.ToString(row[col])?.Trim();
                        if (!string.IsNullOrEmpty(rel))
                        {
                            string fullPath = Path.Combine(storageRoot,
                                rel.TrimStart('~', '/', '\\').Replace("/", Path.DirectorySeparatorChar.ToString()));
                            if (System.IO.File.Exists(fullPath))
                                filePaths.Add(fullPath);
                        }
                    }
                }

                // ✅ Use the universal ZIP helper
                var (zipBytes, zipName) = ApiHelper.ZipHelper.CreateZipFile(excelFilePath, filePaths, "EventDetails.zip");

                // ✅ Step 6: Cleanup temporary files (Excel + folder)
                try
                {
                    if (Directory.Exists(basePath))
                    {
                        Directory.Delete(basePath, recursive: true);
                    }
                }
                catch (Exception ex)
                {
                    // Log only, don’t break flow
                    Console.WriteLine($"[Cleanup Warning] Failed to delete temp folder: {ex.Message}");
                }

                // Step 2: Add extra info into outObj
                outObj.ExtraData["ZIP_DETAILS"] = new
                {
                    ExcelFilePath = excelFilePath,
                    FilePaths = filePaths,  // list or array of paths
                    ZipName = zipName,
                    Message = $"Zip created successfully with {filePaths?.Count ?? 0} files."
                };

                return (zipBytes, "application/zip", "EventDetails.zip", outObj);



            }, nameof(DownloadDetailsDataInZip), out _, skipTokenCheck: false);

        }

        [HttpPost("DownloadEventDetailsZip")]

        public IActionResult DownloadEventDetailsZip([FromBody] object input)
        {

            return ExecuteWithHandlingFile(() =>
            {
                // Step 1: Prepare wrapper and parameters
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

                // Step 2: Get data from DB
                DataTable dt = _core.ExecProcDt("ReactDownloadEventDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                if (outObj.StatusCode != 200)
                {
                    //return (Array.Empty<byte>(), "application/json", "error.json", outObj);

                    outObj.StatusCode = outObj.StatusCode == 0 ? 500 : outObj.StatusCode;
                    outObj.Message = string.IsNullOrEmpty(outObj.Message)
                        ? "No data available or error occurred."
                        : outObj.Message;

                    // Instead of returning an empty file, return JSON
                    return (null, "application/json", "error.json", outObj);
                }



                // Step 3: Create Excel (excluding file path columns)
                string folderName = $"{pJWT_MP_SEAT_ID}_Event_Data_{DateTime.Now:yyyyMMdd_HHmmss}";
                string basePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "image", $"MP_{pJWT_MP_SEAT_ID}", "Download", folderName);
                Directory.CreateDirectory(basePath);

                string excelFilePath = Path.Combine(basePath, $"{folderName}.xlsx");

                // Create a clean DataTable for Excel (exclude file/path columns)
                // 3️⃣ Remove file/path columns for Excel only
                DataTable dtForExcel = dt.Copy();
                var fileColumns = dt.Columns.Cast<DataColumn>() // ✅ FIX: use original dt, not dtForExcel
                    .Where(c => c.ColumnName.ToUpper().Contains("FILE_PATH") || c.ColumnName.ToUpper().Contains("FILE"))
                    .ToList();

                var excelColumnsToRemove = dtForExcel.Columns.Cast<DataColumn>()
                    .Where(c => c.ColumnName.ToUpper().Contains("FILE_PATH") || c.ColumnName.ToUpper().Contains("FILE"))
                    .ToList();

                foreach (var col in excelColumnsToRemove)
                    dtForExcel.Columns.Remove(col);

                // 4️⃣ Create Excel file
                using (var workbook = new XLWorkbook())
                {
                    var ws = workbook.Worksheets.Add("Event Details");
                    ws.Cell(1, 1).InsertTable(dtForExcel, "Events", true);
                    workbook.SaveAs(excelFilePath);
                }

                // Step 5: Create ZIP safely
                //byte[] zipBytes;
                string storageRoot = _settings.BasePath;//@"E:\CORE_PROJECTS\MpAttachedFiles"; //// main file storage path
                List<string> filePaths = new List<string>();
                foreach (DataRow row in dt.Rows)
                {
                    foreach (var col in fileColumns)
                    {
                        string? rel = Convert.ToString(row[col])?.Trim();
                        if (!string.IsNullOrEmpty(rel))
                        {
                            string fullPath = Path.Combine(storageRoot,
                                rel.TrimStart('~', '/', '\\').Replace("/", Path.DirectorySeparatorChar.ToString()));
                            if (System.IO.File.Exists(fullPath))
                                filePaths.Add(fullPath);
                        }
                    }
                }

                // ✅ Use the universal ZIP helper
                var (zipBytes, zipName) = ApiHelper.ZipHelper.CreateZipFile(excelFilePath, filePaths, "EventDetails.zip");

                // ✅ Step 6: Cleanup temporary files (Excel + folder)
                try
                {
                    if (Directory.Exists(basePath))
                    {
                        Directory.Delete(basePath, recursive: true);
                    }
                }
                catch (Exception ex)
                {
                    // Log only, don’t break flow
                    Console.WriteLine($"[Cleanup Warning] Failed to delete temp folder: {ex.Message}");
                }

                // Step 2: Add extra info into outObj
                outObj.ExtraData["ZIP_DETAILS"] = new
                {
                    ExcelFilePath = excelFilePath,
                    FilePaths = filePaths,  // list or array of paths
                    ZipName = zipName,
                    Message = $"Zip created successfully with {filePaths?.Count ?? 0} files."
                };

                return (zipBytes, "application/zip", "EventDetails.zip", outObj);



            }, nameof(DownloadEventDetailsZip), out _, skipTokenCheck: false);

        }

        [HttpPost("ExportFromDataTable")]
        public IActionResult ExportFromDataTable([FromBody] object input)
        {
            return ExecuteWithHandlingFile(() =>
            {
                // ------------------------------------
                // 1. Prepare wrapper & input
                // ------------------------------------
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData);
                var filterKeys = ApiHelper.GetFilteredKeys(data);
                var (pSearch, pageIndex, pageSize) = ApiHelper.GetSearchAndPagingObject(data);

                // ------------------------------------
                // 2. Build SQL params
                // ------------------------------------
                var (paramList, pStatus, pMsg, _, _) = SqlParamBuilderWithAdvanced.BuildAdvanced(
                    data: data,
                    keys: filterKeys,
                    mpSeatId: pJWT_MP_SEAT_ID,
                    includeTotalCount: false,
                    includeWhere: false
                );

                var FILE_NAME = new SqlParameter("@pFILE_NAME", SqlDbType.NVarChar, -1)
                {
                    Direction = ParameterDirection.Output
                };
                paramList.Add(FILE_NAME);
                var TITLE = new SqlParameter("@pTITLE", SqlDbType.NVarChar, -1)
                {
                    Direction = ParameterDirection.Output
                };
                paramList.Add(TITLE);

                // ------------------------------------
                // 3. Execute SP
                // ------------------------------------
                DataTable dt = _core.ExecProcDt("ReactExportDataDetails", paramList.ToArray());
                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ------------------------------------
                // 4. Error / No data
                // ------------------------------------
                if (outObj.StatusCode != 200 || dt == null || dt.Rows.Count == 0)
                {
                    outObj.StatusCode = outObj.StatusCode == 0 ? 500 : outObj.StatusCode;
                    outObj.Message = string.IsNullOrEmpty(outObj.Message)
                        ? "No data available or error occurred."
                        : outObj.Message;

                    //return (null, "application/json", "error.json", outObj);
                    return (Array.Empty<byte>(), "application/json", "error.json", outObj);
                }

                // ------------------------------------
                // 5. Resolve export params (NON NULL)
                // ------------------------------------
                string exportType =
                    data.TryGetValue("EXPORT_TYPE", out var et) && !string.IsNullOrWhiteSpace(et?.ToString())
                        ? et.ToString()!
                        : "PDF";

                string fileName = FILE_NAME.Value != DBNull.Value
                    ? Convert.ToString(FILE_NAME.Value)!
                    : $"Export_{DateTime.Now:yyyyMMddHHmmss}";

                string title = TITLE.Value != DBNull.Value
                    ? Convert.ToString(TITLE.Value)!
                    : "Details Report";

                string? Reportflag = data.ContainsKey("REPORT_FLAG") ? data["REPORT_FLAG"]?.ToString() : "";

                // 2. Extract image bytes from PATH / URL
                List<ImagePdfItem> images = new List<ImagePdfItem>();

                if (exportType.Equals("IMAGE_TO_PDF", StringComparison.OrdinalIgnoreCase)
                 && dt.Columns.Contains("FILE_PATH"))
                {
                    foreach (DataRow row in dt.Rows)
                    {
                        string? imagePathOrUrl = row["FILE_PATH"]?.ToString();
                        title = row["IMAGE_TITLE"]?.ToString() ?? "Image";

                        var imgBytes = GetImageBytes(imagePathOrUrl);

                        if (imgBytes != null)
                        {
                            images.Add(new ImagePdfItem
                            {
                                ImageBytes = imgBytes,
                                Title = title
                            });
                        }

                    }
                }

                // ------------------------------------
                // 6. Export
                // ------------------------------------

                byte[] bytes = _exportService.ExportFromDataTable(
                  dt,
                  exportType ?? "PDF",
                  fileName ?? "Default",
                  title ?? "Data",
                   images,                   // 👈 IMPORTANT FIX
                  out string contentType
                 //out string fileName
                 );

                //return (bytes, contentType, fileName, outObj);
                return (bytes, contentType, fileName ?? "response.json", outObj);

            }, nameof(ExportFromDataTable), out _, skipTokenCheck: false);
        }

        public class ImagePdfItem
        {
            public byte[] ImageBytes { get; set; }
            public string Title { get; set; }
        }

        private byte[] GetImageBytes(string? pathOrUrl)
        {
            if (string.IsNullOrWhiteSpace(pathOrUrl))
                return null;

            try
            {
                // URL
                if (pathOrUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                {
                    using var client = new WebClient();
                    return client.DownloadData(pathOrUrl);
                }

                // Local file
                if (System.IO.File.Exists(pathOrUrl))
                {
                    return System.IO.File.ReadAllBytes(pathOrUrl);
                }
            }
            catch
            {
                // swallow broken image errors
            }

            return null;
        }
    }
}
