using Jabalpur_Office.Data;
using Jabalpur_Office.Filters;
using Jabalpur_Office.Models;
using Jabalpur_Office.ServiceCore;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Cors;
using Jabalpur_Office.Helpers;
using static Jabalpur_Office.Helpers.ApiHelper;
using System.Data;
using System.IO.Compression;
using ClosedXML.Excel;


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
        public ZipController(AppDbContext context, IsssCore core, JwtTokenHelper jwtToken, IWebHostEnvironment env, IOptions<StorageSettings> settings) : base(context, core, jwtToken, settings)
        {
            _context = context;
            _core = core;
            _jwtTokenHelper = jwtToken;
            _env = env;
            _settings = settings.Value;
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

                return (zipBytes, "application/zip", "EventDetails.zip", outObj);

            }, nameof(DownloadEventDetailsZip), out _, skipTokenCheck: false);
        }
    }
}
