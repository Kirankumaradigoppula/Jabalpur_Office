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
using Org.BouncyCastle.Asn1.Ocsp;
using System.Data;
using System.Diagnostics;
using System.Globalization;
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

        // this method is kept for reference of the new approach of creating split zips and master zip, which is implemented in the next method DownloadEventDetailsZip. The old method is kept here for reference and can be removed after confirming the new implementation works as expected.
        /*[HttpPost("DownloadEventDetailsZip")]
        public IActionResult DownloadEventDetailsZip([FromBody] object input)
        {
            return ExecuteWithHandlingFile(() =>
            {
                // Step 1: Prepare wrapper and parameters
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData);
                var filterKeys = ApiHelper.GetFilteredKeys(data);

                // ====================================================
                // DATE VALIDATION
                // ====================================================

                DateTime fromDate = DateTime.ParseExact(data["FROM_DATE"]?.ToString() ?? "", "dd-MM-yyyy", CultureInfo.InvariantCulture);
                DateTime toDate   = DateTime.ParseExact(data["TO_DATE"]?.ToString() ?? "", "dd-MM-yyyy", CultureInfo.InvariantCulture);

                if ((toDate - fromDate).TotalDays > 365)
                {
                    outObj.StatusCode = 400;
                    outObj.Message = "Maximum 1 year data allowed.";
                    return (null, "application/json", "", outObj);

                }

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

                // =====================================================
                // VALIDATION
                // =====================================================
                if (outObj.StatusCode != 200)
                {
                    return (null, "application/json", "", outObj);
                }
                if (dt.Rows.Count <= 0)
                {
                    outObj.StatusCode = 404;
                    outObj.Message = "No data found.";
                    return (null, "application/json", "", outObj);
                }

                // =====================================================
                // STEP 3 : CREATE FOLDER
                // =====================================================
                string folderName = $"{pJWT_MP_SEAT_ID}_Event_Data_{DateTime.Now:yyyyMMdd_HHmmss}";
                string basePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "image", $"MP_{pJWT_MP_SEAT_ID}", "Download", folderName);
                Directory.CreateDirectory(basePath);

                // =====================================================
                // STEP 4 : CREATE EXCEL
                // =====================================================
                string excelFilePath = Path.Combine(basePath, $"{folderName}.xlsx");

                DataTable dtForExcel = dt.Copy();

                var fileColumns = dt.Columns.Cast<DataColumn>() // ✅ FIX: use original dt, not dtForExcel
                    .Where(c => c.ColumnName.ToUpper().Contains("FILE_PATH") || c.ColumnName.ToUpper().Contains("FILE"))
                    .ToList();

                var excelColumnsToRemove = dtForExcel.Columns.Cast<DataColumn>()
                    .Where(c => c.ColumnName.ToUpper().Contains("FILE_PATH") || c.ColumnName.ToUpper().Contains("FILE"))
                    .ToList();

                foreach (var col in excelColumnsToRemove)
                {
                    dtForExcel.Columns.Remove(col);
                }

                using (var workbook = new XLWorkbook())
                {
                    var ws = workbook.Worksheets.Add("Event Details");
                    ws.Cell(1, 1).InsertTable(dtForExcel, "Events", true);
                    workbook.SaveAs(excelFilePath);
                }

                // =====================================================
                // STEP 5 : COLLECT FILES
                // =====================================================

                string storageRoot = _settings.BasePath;

                List<string> filePaths = new();

                foreach (DataRow row in dt.Rows)
                {
                    foreach (var col in fileColumns)
                    {
                        string? rel = Convert.ToString(row[col])?.Trim();

                        if (string.IsNullOrEmpty(rel))
                            continue;

                        string fullPath = Path.Combine(storageRoot, rel.TrimStart('~', '/', '\\')
                                       .Replace("/", Path.DirectorySeparatorChar.ToString()));

                        if (System.IO.File.Exists(fullPath))
                        {
                            filePaths.Add(fullPath);
                        }

                    }
                    
                }

                // =====================================================
                // STEP 6 : CREATE SPLIT ZIPS
                // =====================================================

                List<string> splitZipFiles =
                  NewZipHelper
                  .CreateMonthWiseSplitZipFiles(
                      dt,
                      fileColumns,
                      storageRoot,
                     basePath
                 );

                //List<string> splitZipFiles = 
                //   NewZipHelper.CreateSplitZipFiles(
                //             excelFilePath,
                //             filePaths,
                //             basePath,
                //             "EventDetails"
                //   );
                // =====================================================
                // STEP 7 : ZIP DETAILS
                // =====================================================
                List<ZipPartInfo> zipParts = new();

                foreach (string zipFile in splitZipFiles)
                {
                    FileInfo fi = new(zipFile);

                    string relativePath =
                       Path.GetRelativePath(
                         Path.Combine(
                        Directory.GetCurrentDirectory(),
                        "wwwroot"
                       ),
                    zipFile
                    ).Replace("\\", "/");

                    string monthKey =
                        fi.Directory?.Name ?? "";

                    zipParts.Add(
                        new ZipPartInfo
                        {
                            MonthKey = monthKey,


                            FileName = fi.Name,
                            DownloadUrl =
                                 $"{Request.Scheme}://" +
                                 $"{Request.Host}/" +
                                 $"{relativePath}",

                            SizeBytes = fi.Length,

                            SizeMB = Math.Round(fi.Length / 1024d / 1024d, 2)
                        });

                }

                outObj.ExtraData["ZIP_DETAILS"] =
                 new
                 {
                     TotalMonths = zipParts
                              .Select(x => x.MonthKey)
                              .Distinct()
                              .Count(),

                     TotalZipParts = zipParts.Count,

                     ZipParts = zipParts,

                     Message = $"Created " + $"{zipParts.Count} " + $"zip files successfully."



                 };

               return (null, "application/json", "", outObj);
            }, nameof(DownloadEventDetailsZip), out _, skipTokenCheck: false);

        }*/

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

                // ✅ Use the universal ZIP helper --21052026
                //var (zipBytes, zipName) = ApiHelper.ZipHelper.CreateZipFile(excelFilePath, filePaths, "EventDetails.zip");

                // =====================================================
                // STEP 6 : CREATE SPLIT ZIPS
                // =====================================================

                List<string> splitZipFiles =
                    ApiHelper.ZipHelper.CreateSplitZipFiles(
                        excelFilePath,
                        filePaths,
                        basePath,
                        "EventDetails");
                // =====================================================
                //  CREATE MASTER ZIP
                // =====================================================

                string finalZipPath =
                    ApiHelper.ZipHelper.CreateMasterZip(
                        splitZipFiles,
                        basePath,
                        "EventDetails.zip");

                // =====================================================
                // STEP 8 : READ SAFE ZIP
                // =====================================================

                byte[] zipBytes =
                    System.IO.File.ReadAllBytes(
                        finalZipPath);

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
                    //ZipName = zipName,
                    TotalFiles =
                    filePaths.Count,

                    SplitZipFiles =
                    splitZipFiles.Select(
                        x => Path.GetFileName(x))
                        .ToList(),

                    FinalZip =
                    Path.GetFileName(
                        finalZipPath),
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

        [HttpPost("GenerateExcelZipArchiveAsync")]
        public IActionResult GenerateExcelZipArchiveAsync([FromBody] object input)
        {
            return ExecuteExportWithHandlingFile(() =>
            {
                // ------------------------------------
                // 1. Prepare Input
                // ------------------------------------
                var (outObj, rawData) = PrepareWrapperAndData<WrapperListData>(input ?? new { });
                var data = ApiHelper.ToObjectDictionary(rawData);
                var filterKeys = ApiHelper.GetFilteredKeys(data);
                var (pSearch, pageIndex, pageSize) = ApiHelper.GetSearchAndPagingObject(data);



                // ------------------------------------
                // 2. SQL Parameters
                // ------------------------------------
                var (paramList, pStatus, pMsg, _, pWhere) =
                    SqlParamBuilderWithAdvanced.BuildAdvanced(
                        data,
                        filterKeys,
                        pJWT_MP_SEAT_ID,
                        includeTotalCount: false,
                        includeWhere: true
                    );

                var FILE_NAME = new SqlParameter("@pFILE_NAME", SqlDbType.NVarChar, -1)
                {
                    Direction = ParameterDirection.Output
                };

                var TITLE = new SqlParameter("@pTITLE", SqlDbType.NVarChar, -1)
                {
                    Direction = ParameterDirection.Output
                };

                var ZIP_EXCEL_STATUS = new SqlParameter("@pZIP_EXCEL_STATUS", SqlDbType.VarChar, 5)
                {
                    Direction = ParameterDirection.Output
                };

                var ZIP_TEXT_STATUS = new SqlParameter("@pZIP_TEXT_STATUS", SqlDbType.VarChar, 5)
                {
                    Direction = ParameterDirection.Output
                };

                paramList.Add(FILE_NAME);
                paramList.Add(TITLE);
                paramList.Add(ZIP_EXCEL_STATUS);
                paramList.Add(ZIP_TEXT_STATUS);

                // ------------------------------------
                // 3. Execute Stored Procedure
                // ------------------------------------
                DataTable dt = _core.ExecProcDt("ReactGenerateExcelZipArchiveAsync", paramList.ToArray());

                ApiHelper.SetDataTableListOutput(dt, outObj);
                SetOutput(pStatus, pMsg, outObj);

                // ------------------------------------
                // 4. Validate Data
                // ------------------------------------
                if (outObj.StatusCode != 200 || dt == null || dt.Rows.Count == 0)
                {
                    outObj.StatusCode = outObj.StatusCode == 0 ? 500 : outObj.StatusCode;
                    outObj.Message ??= "No data available.";

                    return new FileResponse { Meta = outObj };
                }

                // ------------------------------------
                // 5. Resolve Params
                // ------------------------------------
                string exportType = data.ContainsKey("EXPORT_TYPE")
                    ? data["EXPORT_TYPE"]?.ToString() ?? "PDF"
                    : "PDF";

                string fileName = FILE_NAME.Value != DBNull.Value
                    ? FILE_NAME.Value.ToString()!
                    : $"Export_{DateTime.Now:yyyyMMddHHmmss}";

                string title = TITLE.Value != DBNull.Value
                    ? TITLE.Value.ToString()!
                    : "Details Report";

                // ------------------------------------
                // 6. ZIP Export
                // ------------------------------------
                if (exportType.Equals("ZIP", StringComparison.OrdinalIgnoreCase))
                {

                    

                    // =====================================================
                    // CHECK TOTAL FILE SIZE
                    // =====================================================
                    long totalBytes = 0;

                    foreach (DataRow row in dt.Rows) 
                    {

                        string root = _settings.BasePath;

                        string? filePath = Path.Combine(root, row["FILE_PATH"]?.ToString() ?? "");

                        if (string.IsNullOrWhiteSpace(filePath) || !System.IO.File.Exists(filePath))
                        {
                            continue;
                        }

                        FileInfo fileInfo = new FileInfo(filePath);
                        totalBytes += fileInfo.Length;

                    }

                    // =====================================================
                    // MAX SIZE = 1 GB
                    // =====================================================
                    const long MAX_ZIP_SIZE = 1024L * 1024L * 1024L;

                    if (totalBytes > MAX_ZIP_SIZE)
                    {
                        outObj.StatusCode = 400;
                        outObj.Message =
                          "ZIP export exceeds the maximum allowed size of 1 GB. Please apply filters or export smaller batches.";

                        return new FileResponse
                        {
                            Meta = outObj
                        };
                    }

                    // =====================================================
                    // ZIP EXCEL STATUS
                    // =====================================================
                    bool includeExcel =
                        string.Equals(
                             ZIP_EXCEL_STATUS.Value?.ToString(),
                            "Y",
                            StringComparison.OrdinalIgnoreCase
                        );


                    // =====================================================
                    // START ZIP CREATION TIMER
                    // =====================================================
                    var stopwatch = Stopwatch.StartNew();
                    using var memoryStream = new MemoryStream();

                    using (var archive = new ZipArchive(memoryStream, ZipArchiveMode.Create, true))
                    {

                        // =============================================
                        // GROUP RECORDS
                        // =============================================

                        var groupedFiles = dt.AsEnumerable().GroupBy(x =>
                                          x["ID"]?.ToString()
                                          ?? "UNKNOWN"
                                      ).ToList();

                        // =====================================================
                        // GENERATE EXCEL ONLY IF STATUS = Y
                        // =====================================================
                        if (includeExcel)
                        {

                        
                             // =====================================================
                             // CREATE EXCEL DATA (WITHOUT FILE_PATH)
                             // =====================================================
                             
                             DataTable excelTable = dt.Copy();
                             
                             // remove physical path
                             if (excelTable.Columns.Contains("FILE_PATH"))
                             {
                                 excelTable.Columns.Remove("FILE_PATH");
                             }

                       

                             // =============================================
                             // CREATE UNIQUE ROWS
                             // =============================================
                             DataTable finalExcelTable = excelTable.Clone();
                            
                             foreach (var group in groupedFiles)
                             {
                                 var firstRow =
                                     group.First();
                            
                                 DataRow newRow =
                                     finalExcelTable.NewRow();
                            
                                 foreach (
                                     DataColumn col
                                     in excelTable.Columns
                                 )
                                 {
                                     newRow[col.ColumnName] =
                                         firstRow[col.ColumnName];
                                 }
                            
                                 finalExcelTable.Rows.Add(
                                     newRow
                                 );
                             }
                            
                            
                             using var excelStream = new MemoryStream();
                            
                             using (var workbook = new ClosedXML.Excel.XLWorkbook())
                             {
                            
                                 // =============================================
                                 // CREATE WORKSHEET
                                 // =============================================
                                 var worksheet = workbook.Worksheets.Add("Data");
                            
                                 worksheet.Cell(1, 1).InsertTable(finalExcelTable);
                            
                                 // =============================================
                                 // FILE_NAME COLUMN INDEX
                                 // =============================================
                            
                                 int fileColumn = finalExcelTable.Columns["FILE_NAME"].Ordinal + 1;
                            
                                 int rowIndex = 2;
                            
                                 // =========================================
                                 // HYPERLINKS
                                 // =========================================
                                 foreach (var group in groupedFiles)
                                 {
                                     string recordId = group.Key;
                                     int totalFiles = group.Count();
                                     var firstRow = group.First();
                            
                                     string originalPath = firstRow["FILE_PATH"]?.ToString() ?? "";
                                     string extension = Path.GetExtension(originalPath);
                                     string fileNameInZip = firstRow["FILE_NAME"]?.ToString() ?? "FILE";
                            
                                     if (!Path.HasExtension(fileNameInZip))
                                     {
                                         fileNameInZip += extension;
                                     }
                                     foreach (char c in Path.GetInvalidFileNameChars())
                                     {
                                         fileNameInZip = fileNameInZip.Replace(c,'_');
                                     }
                            
                                     var cell = worksheet.Cell(rowIndex, fileColumn);
                            
                                     string hyperlinkPath;
                            
                                     // =====================================
                                     // SINGLE FILE
                                     // =====================================
                                     if (totalFiles == 1)
                                     {
                                         cell.Value = fileNameInZip;
                                         hyperlinkPath = $"FILES/{fileNameInZip}";
                                     }
                                     // =====================================
                                     // MULTIPLE FILES
                                     // =====================================
                                     else
                                     {
                                         cell.Value = "Open Folder";
                                         hyperlinkPath =    $"FILES/{recordId}/";
                                     }
                            
                                     // =====================================
                                     // HYPERLINK
                                     // =====================================
                            
                                     cell.SetHyperlink(
                                            new XLHyperlink(
                                                 new Uri(hyperlinkPath, UriKind.Relative)
                                                )
                                         );
                            
                                     cell.Style.Font.FontColor = XLColor.Blue;
                                     cell.Style.Font.Underline = XLFontUnderlineValues.Single;
                                     rowIndex++;
                                 }
                            
                                 // =========================================
                                 // DESIGN
                                 // =========================================
                                 worksheet.SheetView.FreezeRows(1);
                                 worksheet.Columns().AdjustToContents();
                                 workbook.SaveAs(excelStream);
                            
                            
                             }

                             excelStream.Position = 0;
                             
                             // =====================================================
                             // ADD EXCEL FILE TO ZIP
                             // =====================================================
                             
                             var excelEntry = archive.CreateEntry($"{fileName}.xlsx");
                             
                             using (var entryStream = excelEntry.Open())
                             {
                                 excelStream.CopyTo(entryStream);
                             }
                         }    
                        // =============================================================
                        // ADD FILES TO ZIP
                        // =============================================================
                        foreach (var group in groupedFiles)
                        {
                            string recordId = group.Key;

                            int totalFiles = group.Count();

                            // =========================================================
                            // SINGLE FILE
                            // =========================================================
                            if (totalFiles == 1)
                            {
                                var row = group.First();

                                string originalPath = row["FILE_PATH"]?.ToString() ?? "";

                                string extension = Path.GetExtension(originalPath);

                                string fileNameInZip = row["FILE_NAME"]?.ToString() ?? "FILE";

                                if (!Path.HasExtension(fileNameInZip))
                                {
                                    fileNameInZip += extension;
                                }

                                foreach (char c in Path.GetInvalidFileNameChars())
                                {
                                    fileNameInZip =
                                        fileNameInZip.Replace(c, '_');
                                }

                                string fullPath =
                                   Path.Combine(
                                       _settings.BasePath,
                                       originalPath
                                   );

                                if (!System.IO.File.Exists(fullPath))
                                    continue;

                                var entry = archive.CreateEntry($"FILES/{fileNameInZip}");

                                using var entryStream = entry.Open();

                                using var fileStream =
                                   new FileStream(
                                       fullPath,
                                       FileMode.Open,
                                       FileAccess.Read
                                   );

                                fileStream.CopyTo(entryStream);

                            }
                            // =========================================================
                            // MULTIPLE FILES
                            // =========================================================
                            else
                            {
                                foreach (var row in group)
                                {
                                    string originalPath = row["FILE_PATH"]?.ToString() ?? "";
                                    string extension = Path.GetExtension(originalPath);
                                    string fileNameInZip = row["FILE_NAME"]?.ToString() ?? "FILE";

                                    if (!Path.HasExtension(fileNameInZip))
                                    {
                                        fileNameInZip += extension;
                                    }

                                    foreach (char c in Path.GetInvalidFileNameChars())
                                    {
                                        fileNameInZip =
                                            fileNameInZip.Replace(c, '_');
                                    }

                                    string fullPath =
                                        Path.Combine(
                                            _settings.BasePath,
                                            originalPath
                                        );

                                    if (!System.IO.File.Exists(fullPath))
                                        continue;

                                    var entry =
                                        archive.CreateEntry(
                                            $"FILES/{recordId}/{fileNameInZip}"
                                        );

                                    using var entryStream =
                                        entry.Open();

                                    using var fileStream =
                                        new FileStream(
                                            fullPath,
                                            FileMode.Open,
                                            FileAccess.Read
                                        );

                                    fileStream.CopyTo(entryStream);
                                }
                            }

                        }

                        
                    }

                    stopwatch.Stop();

                    memoryStream.Position = 0;

                    outObj.ExtraData["ZIP_GENERATION_MS"] =
                               stopwatch.ElapsedMilliseconds;

                    outObj.ExtraData["ZIP_SIZE_MB"] =
                        Math.Round(
                            memoryStream.Length / 1024d / 1024d,
                            2
                        );

                    return new FileResponse
                    {
                        Bytes = memoryStream.ToArray(),
                        ContentType = "application/zip",
                        FileName = fileName + ".zip",
                        Meta = outObj
                    };
                }

                // ------------------------------------
                // 7. IMAGE → PDF
                // ------------------------------------
                List<ImagePdfItem> images = new();

                if (exportType.Equals("IMAGE_TO_PDF", StringComparison.OrdinalIgnoreCase)
                    && dt.Columns.Contains("FILE_PATH"))
                {
                    foreach (DataRow row in dt.Rows)
                    {
                        string? path = row["FILE_PATH"]?.ToString();
                        var imgBytes = GetImageBytes(path);

                        if (imgBytes != null)
                        {
                            images.Add(new ImagePdfItem
                            {
                                ImageBytes = imgBytes,
                                Title = row["IMAGE_TITLE"]?.ToString() ?? "Image"
                            });
                        }
                    }
                }

                // ------------------------------------
                // 8. NORMAL EXPORT (PDF / Excel)
                // ------------------------------------
                byte[] bytes = _exportService.ExportFromDataTable(
                    dt,
                    exportType,
                    fileName,
                    title,
                    images,
                    out string contentType
                );

                return new FileResponse
                {
                    Bytes = bytes,
                    ContentType = contentType,
                    FileName = fileName,
                    Meta = outObj
                };


            }, nameof(GenerateExcelZipArchiveAsync), out _, false);
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
