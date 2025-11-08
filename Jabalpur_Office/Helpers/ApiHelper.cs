using System.Data;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using iTextSharp.text.pdf;
using iTextSharp.text;
using Jabalpur_Office.Models;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore.Query.SqlExpressions;
using Newtonsoft.Json;

namespace Jabalpur_Office.Helpers
{
    public static class ApiHelper
    {

        public static bool IsTokenValid(string loginStatus, out Product response)
        {
            response = new Product();
            if (string.IsNullOrEmpty(loginStatus))
            {
                response.StatusCode = 401;
                response.Message = "Unauthorized or token expired..";
                return false;
            }
            return true;
        }
        public static List<Dictionary<string, string>> ConvertToDictionaryList(DataTable dt)
        {
            if (dt == null || dt.Rows.Count == 0)
                return new List<Dictionary<string, string>>();

            return dt.AsEnumerable()
                     .Select(row => dt.Columns.Cast<DataColumn>()
                         .ToDictionary(
                             col => col.ColumnName,
                             col => row[col]?.ToString() ?? string.Empty
                         ))
                     .ToList();
        }
        public static void SetOutputParams(SqlParameter statusParam, SqlParameter messageParam,  Product response)
        {
            if (response == null) throw new ArgumentNullException(nameof(response));

            response.StatusCode = statusParam?.Value != DBNull.Value && statusParam?.Value != null
                ? Convert.ToInt32(statusParam.Value)
                : 500;

            response.Message = messageParam?.Value?.ToString() ?? "Unknown error";

            

        }



        public static void SetOutputParamsWithRetId(SqlParameter statusParam, SqlParameter messageParam, SqlParameter RetIDParam, Product response)
        {
            if (response == null) throw new ArgumentNullException(nameof(response));

            response.StatusCode = statusParam?.Value != DBNull.Value && statusParam?.Value != null
                ? Convert.ToInt32(statusParam.Value)
                : 500;

            response.Message = messageParam?.Value?.ToString() ?? "Unknown error";

            // ✅ Only assign RetID if the response is CRUD type
            if (response is WrapperCrudObjectData wrapper)
            {
                wrapper.RetID = RetIDParam?.Value != DBNull.Value && RetIDParam?.Value != null
                    ? Convert.ToInt32(RetIDParam.Value)
                    : 0;
            }
        }

        //

        public static SqlParameter OutputParam(string name, SqlDbType type, int size = 0)
        {
            var param = new SqlParameter(name, type)
            {
                Direction = ParameterDirection.Output
            };

            if (size > 0)
                param.Size = size;

            return param;
        }

        public static string GetValue(Dictionary<string, string> data, string key)
        {
            if (data == null || string.IsNullOrWhiteSpace(key))
                return string.Empty;

            return data.TryGetValue(key, out var value)
                ? value?.Trim() ?? string.Empty
                : string.Empty;
        }

        public static object GetDbValue(string value)
        {
            return string.IsNullOrWhiteSpace(value)
                ? DBNull.Value
                : (object)value.Trim();
        }



        public static Dictionary<string, object> GetValuesOrDbNull(Dictionary<string, string> data, params string[] keys)
        {
            return keys.ToDictionary(
                key => key,
                key => data != null && data.TryGetValue(key, out string value) && !string.IsNullOrWhiteSpace(value)
                    ? (object)value.Trim()
                    : DBNull.Value
            );
        }


        public static void SetSingleRowOutput(DataTable dt, IHasDataObject model)
        {
            model.DataObject = dt != null && dt.Rows.Count > 0
                ? dt.Columns.Cast<DataColumn>()
                    .ToDictionary(col => col.ColumnName, col => dt.Rows[0][col]?.ToString() ?? string.Empty)
                : null;
        }

        public static void SetDataTableListOutput(DataTable dt, IHasDataList model)
        {
            if (model == null || dt == null)
            {
                model.DataList = new List<Dictionary<string, string>>();
                return;
            }

            model.DataList = dt.AsEnumerable()
                .Select(row => dt.Columns.Cast<DataColumn>()
                    .ToDictionary(
                        col => col.ColumnName,
                        col => row[col]?.ToString() ?? string.Empty
                    ))
                .ToList();
        }

        public static class SqlParamBuilder
        {
            public static (List<SqlParameter> ParamList, SqlParameter pStatus, SqlParameter pMsg) BuildWithOutput(
                Dictionary<string, object> values,
                IEnumerable<string> keys,
                object mpSeatId = null,
                object userId = null)
            {
                var paramList = new List<SqlParameter>();

                // Optional MP_SEAT_ID
                if (mpSeatId != null)
                {
                    paramList.Add(new SqlParameter("@pMP_SEAT_ID", mpSeatId));
                }

                // Input parameters from dictionary
                foreach (var key in keys)
                {
                    var paramValue = values != null && values.ContainsKey(key)
                        ? values[key] ?? DBNull.Value
                        : DBNull.Value;

                    paramList.Add(new SqlParameter($"@p{key}", paramValue));
                }

                // Optional USERID
                if (userId != null)
                {
                    paramList.Add(new SqlParameter("@pUSERID", userId));
                }

                // Output: Message
                var pMsg = new SqlParameter("@pMessage", SqlDbType.NVarChar, 500)
                {
                    Direction = ParameterDirection.Output,
                    Value = DBNull.Value
                };

                // Output: Status
                var pStatus = new SqlParameter("@pStatusCode", SqlDbType.VarChar, 10)
                {
                    Direction = ParameterDirection.Output,
                    Value = DBNull.Value
                };

                // Add outputs to list
                paramList.Add(pMsg);
                paramList.Add(pStatus);

                return (paramList, pStatus, pMsg);
            }
        }

        // data Object
        public static Dictionary<string, object> GetValuesOrDbNullObject(
           Dictionary<string, object> data,
           params string[] keys)
        {
            if (data == null || keys == null)
                return new Dictionary<string, object>();

            return keys.ToDictionary(
                key => key,
                key =>
                    data.TryGetValue(key, out var value) &&
                    value != null &&
                    !string.IsNullOrWhiteSpace(value.ToString())
                        ? value
                        : DBNull.Value
            );
        }

        // data Object

        // <summary>
        /// Converts Dictionary&lt;string, string&gt; to Dictionary&lt;string, object&gt; with:
        /// - Trimmed and UPPERCASE keys
        /// - DBNull.Value for null/empty values
        /// </summary>

        public static Dictionary<string, object> ToObjectDictionary(Dictionary<string, string> rawData)
        {
            var result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

            if (rawData == null)
                return result;

            foreach (var kvp in rawData)
            {
                if (string.IsNullOrWhiteSpace(kvp.Key)) continue;

                var key = kvp.Key.Trim().ToUpperInvariant();
                var value = string.IsNullOrWhiteSpace(kvp.Value) ? DBNull.Value : (object)kvp.Value.Trim();

                // Add only if key doesn't already exist (case-insensitive)
                if (!result.ContainsKey(key))
                    result[key] = value;
            }

            return result;
        }

        // Generic version
        public static T ToObject<T>(object input)
        {
            if (input == null) return default(T);

            if (input is string s)
                return JsonConvert.DeserializeObject<T>(s);

            return JsonConvert.DeserializeObject<T>(input.ToString());
        }

        // Non-generic version (always Dictionary<string, object>)
        public static Dictionary<string, object> ToObject(object input)
        {
            if (input == null) return new Dictionary<string, object>();
            return JsonConvert.DeserializeObject<Dictionary<string, object>>(input.ToString());
        }


        // Central list of keys to exclude (like Search, Paging)
        public static readonly string[] ExcludedSearchPagingKeys =
            { "Search", "PageIndex", "PageSize" };

        /// <summary>
        /// Filters out keys used for search and pagination.
        /// </summary>
        public static IEnumerable<string> GetFilteredKeys(Dictionary<string, object> data)
        {
            return data?.Keys
                .Where(k => !ExcludedSearchPagingKeys.Contains(k, StringComparer.OrdinalIgnoreCase))
                ?? Enumerable.Empty<string>();
        }

        /// <summary>
        /// Extracts Search, PageIndex, PageSize from the dictionary
        /// </summary>
        public static (string Search, int? PageIndex, int? PageSize) GetSearchAndPagingObject(Dictionary<string, object> data)
        {
            if (data == null) return (null, null, null);

            string search = data.TryGetValue("Search", out var s) ? s?.ToString() : null;

            int? pageIndex = data.TryGetValue("PageIndex", out var piVal) &&
                             int.TryParse(piVal?.ToString(), out int pi)
                ? pi
                : (int?)null;

            int? pageSize = data.TryGetValue("PageSize", out var psVal) &&
                            int.TryParse(psVal?.ToString(), out int ps)
                ? ps
                : (int?)null;

            return (search, pageIndex, pageSize);
        }

        public static class SqlParamBuilderWithAdvanced
        {
            public static (
                List<SqlParameter> ParamList,
                SqlParameter pStatus,
                SqlParameter pMsg,
                SqlParameter pTotalCount,
                string pWhere
            ) BuildAdvanced(
                Dictionary<string, object> data,
                IEnumerable<string> keys,
                object mpSeatId = null,
                object userId = null,
                bool includeTotalCount = false,
                bool includeWhere = false,
                int? pageIndex = null,
                int? pageSize = null)
            {
                // Ensure data and keys are not null
                //data ??= new Dictionary<string, object>();
                //keys ??= Enumerable.Empty<string>();

                // Extract sanitized values
                var values = ApiHelper.GetValuesOrDbNullObject(data, keys.ToArray());

                // Extract optional search/paging values
                var (search, _, _) = ApiHelper.GetSearchAndPagingObject(data);
                string pWhere = includeWhere ? ApiHelper.ReturnWhere(search) : null;

                var paramList = new List<SqlParameter>();

                // Optional parameters
                if (mpSeatId != null)
                    paramList.Add(new SqlParameter("@pMP_SEAT_ID", mpSeatId));

                foreach (var key in keys)
                {
                    var value = values.ContainsKey(key) ? values[key] ?? DBNull.Value : DBNull.Value;
                    paramList.Add(new SqlParameter($"@p{key}", value));
                }

                if (userId != null)
                    paramList.Add(new SqlParameter("@pUSERID", userId));

                if (!string.IsNullOrWhiteSpace(pWhere))
                    paramList.Add(new SqlParameter("@pWhere", pWhere));

                if (pageIndex.HasValue)
                    paramList.Add(new SqlParameter("@PageNumber", pageIndex.Value));

                if (pageSize.HasValue)
                    paramList.Add(new SqlParameter("@RowspPage", pageSize.Value));

                // Output parameters
                var pStatus = new SqlParameter("@pStatusCode", SqlDbType.VarChar, 10)
                {
                    Direction = ParameterDirection.Output
                };

                var pMsg = new SqlParameter("@pMessage", SqlDbType.VarChar, 500)
                {
                    Direction = ParameterDirection.Output
                };

                paramList.Add(pStatus);
                paramList.Add(pMsg);

                SqlParameter pTotalCount = null;
                if (includeTotalCount)
                {
                    pTotalCount = new SqlParameter("@pTotalCount", SqlDbType.Int)
                    {
                        Direction = ParameterDirection.Output
                    };
                    paramList.Add(pTotalCount);
                }

                return (paramList, pStatus, pMsg, pTotalCount, pWhere);
            }
        }

        public static class SqlParamBuilderWithAdvancedCrud
        {
            public static (
                List<SqlParameter> ParamList,
                SqlParameter pStatus,
                SqlParameter pMsg,
                SqlParameter pRetId
            ) BuildAdvanced(
                Dictionary<string, object> data,
                IEnumerable<string> keys,
                object mpSeatId = null,
                object userId = null,
                bool includeRetId = false
            )
            {
                data ??= new Dictionary<string, object>();
                keys ??= Enumerable.Empty<string>();

                // Clean/null-safe values
                var values = ApiHelper.GetValuesOrDbNullObject(data, keys.ToArray());

                var paramList = new List<SqlParameter>();

                // Optional: MP Seat ID
                if (mpSeatId != null)
                    paramList.Add(new SqlParameter("@pMP_SEAT_ID", mpSeatId));

                // Input parameters
                foreach (var key in keys)
                {
                    var value = values.ContainsKey(key)
                        ? values[key] ?? DBNull.Value
                        : DBNull.Value;

                    paramList.Add(new SqlParameter($"@p{key}", value));
                }

                // Optional: USERID
                if (userId != null)
                    paramList.Add(new SqlParameter("@pUSERID", userId));

                // Output: Status Code
                var pStatus = new SqlParameter("@pStatusCode", SqlDbType.VarChar, 10)
                {
                    Direction = ParameterDirection.Output
                };

                // Output: Message
                var pMsg = new SqlParameter("@pMessage", SqlDbType.NVarChar, 500)
                {
                    Direction = ParameterDirection.Output
                };

                paramList.Add(pStatus);
                paramList.Add(pMsg);

                // Optional: RetID
                SqlParameter pRetId = null;
                if (includeRetId)
                {
                    pRetId = new SqlParameter("@pRetId", SqlDbType.Int)
                    {
                        Direction = ParameterDirection.Output
                    };
                    paramList.Add(pRetId);
                }

                return (paramList, pStatus, pMsg, pRetId);
            }
        }

        /// <summary>
        /// Adds standard output parameters (@pMessage, @pStatusCode) to the parameter list.
        /// </summary>
        /// <param name="paramList">Reference to the list of SQL parameters.</param>
        /// <param name="pStatus">Output parameter reference for status code.</param>
        /// <param name="pMessage">Output parameter reference for message.</param>
        public static void AddStandardOutputParams(
            List<SqlParameter> paramList,
            out SqlParameter pStatus,
            out SqlParameter pMessage)
        {
            // Output: Message
            pMessage = new SqlParameter("@pMessage", SqlDbType.NVarChar, 500)
            {
                Direction = ParameterDirection.Output,
                Value = DBNull.Value
            };

            // Output: Status code (Int or VarChar depending on your SP definition)
            pStatus = new SqlParameter("@pStatusCode", SqlDbType.Int)
            {
                Direction = ParameterDirection.Output,
                Value = DBNull.Value
            };

            paramList.Add(pMessage);
            paramList.Add(pStatus);
        }


        /// <summary>
        /// Adds an output parameter named @pRetId to capture the return identity (usually from insert).
        /// </summary>
        /// <param name="paramList">The parameter list to add to.</param>
        /// <param name="pRetId">The output parameter returned by reference.</param>
        public static void AddRetIdOutputParams(
            List<SqlParameter> paramList,
            out SqlParameter pRetId)
        {
            pRetId = new SqlParameter("@pRetId", SqlDbType.Int)
            {
                Direction = ParameterDirection.Output,
                Value = DBNull.Value
            };

            paramList?.Add(pRetId);
        }

        /// <summary>
        /// Adds a @pTotalCount output parameter to the SQL parameter list.
        /// </summary>
        /// <param name="paramList">The SQL parameter list.</param>
        /// <returns>The output SqlParameter reference.</returns>
        public static SqlParameter AddPaginationOutputParam(List<SqlParameter> paramList)
        {
            var pTotalCount = new SqlParameter("@pTotalCount", SqlDbType.Int)
            {
                Direction = ParameterDirection.Output,
                Value = DBNull.Value
            };

            paramList?.Add(pTotalCount);
            return pTotalCount;
        }

        public static class PaginationHelper
        {
            /// <summary>
            /// Sets pagination info inside the wrapper object from total count.
            /// </summary>
            /// <param name="outObj">The output wrapper object to populate.</param>
            /// <param name="totalCountStr">Total count (from output param).</param>
            /// <param name="pageIndex">Requested page index.</param>
            /// <param name="pageSize">Requested page size.</param>
            public static void ApplyPagination(
                WrapperListData outObj,
                string totalCountStr,
                int pageIndex,
                int pageSize)
            {
                if (outObj == null) return;

                int total = 0;
                int.TryParse(totalCountStr, out total);

                outObj.Pager = new Pager(total, pageIndex, pageSize);
                //outObj.StatusCode = 200;
                
            }
        }

        /// <summary>
        /// Extracts search term, page index, and page size from input dictionary.
        /// </summary>
        /// <param name="data">Input dictionary (e.g. from query or body).</param>
        /// <returns>Tuple: (Search, PageIndex, PageSize)</returns>
        public static (string Search, int PageIndex, int PageSize) GetSearchAndPaging(Dictionary<string, string> data)
        {
            var search = GetValue(data, "Search");

            var pageIndex = int.TryParse(GetValue(data, "PageIndex"), out var idx) && idx > 0
                ? idx
                : 1;

            var pageSize = int.TryParse(GetValue(data, "PageSize"), out var size) && size > 0
                ? size
                : 1000;

            return (search, pageIndex, pageSize);
        }

        public static class DataTableConverter
        {
            /// <summary>
            /// Converts a DataTable into a strongly-typed list of objects of type T.
            /// </summary>
            public static List<T> ToList<T>(DataTable dt) where T : new()
            {
                var result = new List<T>();
                if (dt == null || dt.Rows.Count == 0)
                    return result;

                // Column names (uppercase for matching)
                var columnNames = dt.Columns.Cast<DataColumn>()
                    .Select(c => c.ColumnName.Trim().ToUpperInvariant())
                    .ToHashSet();

                // Fields and properties
                var type = typeof(T);
                var fields = type.GetFields(BindingFlags.Public | BindingFlags.Instance);
                var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                                     .Where(p => p.CanWrite).ToArray();

                foreach (DataRow row in dt.Rows)
                {
                    var obj = new T();

                    // Assign to fields
                    foreach (var field in fields)
                    {
                        if (columnNames.Contains(field.Name.ToUpperInvariant()))
                        {
                            try
                            {
                                var value = row[field.Name];
                                if (value != DBNull.Value)
                                    field.SetValue(obj, ConvertToType(value, field.FieldType));
                            }
                            catch
                            {
                                // Optional: Log error or continue
                            }
                        }
                    }

                    // Assign to properties
                    foreach (var prop in properties)
                    {
                        if (columnNames.Contains(prop.Name.ToUpperInvariant()))
                        {
                            try
                            {
                                var value = row[prop.Name];
                                if (value != DBNull.Value)
                                    prop.SetValue(obj, ConvertToType(value, prop.PropertyType));
                            }
                            catch
                            {
                                // Optional: Log error or continue
                            }
                        }
                    }

                    result.Add(obj);
                }

                return result;
            }

            /// <summary>
            /// Safely converts an object to the given type (handles nullable types).
            /// </summary>
            private static object ConvertToType(object value, Type targetType)
            {
                if (targetType == null || value == null || value == DBNull.Value)
                    return null;

                Type underlyingType = Nullable.GetUnderlyingType(targetType) ?? targetType;

                return Convert.ChangeType(value, underlyingType);
            }
        }


        public static class ZipHelper
        {
            /// <summary>
            /// Creates a ZIP archive in memory containing an Excel file and additional files.
            /// </summary>
            /// <param name="excelFilePath">Full path to the Excel file to include (optional).</param>
            /// <param name="filePaths">List of full file paths to include in the ZIP.</param>
            /// <param name="zipFileName">Name for the ZIP file (only used for download naming).</param>
            /// <returns>Tuple with ZIP bytes and the file name.</returns>
            public static (byte[] ZipBytes, string FileName) CreateZipFile(
                string excelFilePath,
                 //IEnumerable<string> filePaths,
                 List<string> filePaths,
                string zipFileName)
            {
                //if (filePaths == null)
                //    filePaths = Enumerable.Empty<string>();

                byte[] zipBytes;
                using (var memoryStream = new MemoryStream())
                {
                    using (var archive = new ZipArchive(memoryStream, ZipArchiveMode.Create, true))
                    {
                        HashSet<string> addedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        List<string> imageFiles = new();

                        // 1️⃣ Add Excel if provided
                        // ✅ 1️. Add Excel
                        if (File.Exists(excelFilePath))
                        {
                            string excelName = Path.GetFileName(excelFilePath);
                            AddFileToArchive(archive, excelFilePath, excelName, addedNames);
                        }

                        // ✅ 2️. Add all files individually
                        foreach (var path in filePaths)
                        {
                            if (!File.Exists(path)) continue;

                            string entryName = Path.GetFileName(path);
                            string uniqueName = GetUniqueName(entryName, addedNames);
                            AddFileToArchive(archive, path, uniqueName, addedNames);

                            // Collect image files separately for the PDF merge
                            if (IsImageFile(path))
                                imageFiles.Add(path);
                        }

                        // ✅ 3️. Add a merged PDF of all images
                        if (imageFiles.Any())
                        {
                            using (var pdfStream = new MemoryStream())
                            {
                                CreatePdfFromImages(imageFiles, pdfStream);
                                pdfStream.Position = 0;

                                var pdfEntry = archive.CreateEntry("All_Images.pdf");
                                using (var entryStream = pdfEntry.Open())
                                {
                                    pdfStream.CopyTo(entryStream);
                                }
                            }
                        }


                    }

                    zipBytes = memoryStream.ToArray();
                }

                return (zipBytes, zipFileName);
            }
        }

        private static void CreatePdfFromImages(List<string> imagePaths, Stream output)
        {
            using (var doc = new Document(PageSize.A4))
            {
                PdfWriter.GetInstance(doc, output);
                doc.Open();

                foreach (var imgPath in imagePaths)
                {
                    try
                    {
                        var img = iTextSharp.text.Image.GetInstance(imgPath);
                        img.ScaleToFit(doc.PageSize.Width - 40, doc.PageSize.Height - 40);
                        img.Alignment = Element.ALIGN_CENTER;
                        doc.Add(img);
                        doc.NewPage();
                    }
                    catch
                    {
                        // Ignore invalid image formats
                        continue;
                    }
                }

                doc.Close();
            }
        }

        // 🧩 Utilities

        private static void AddFileToArchive(ZipArchive archive, string sourcePath, string entryName, HashSet<string> addedNames)
        {
            if (!File.Exists(sourcePath)) return;

            var entry = archive.CreateEntry(entryName);
            using (var entryStream = entry.Open())
            using (var fileStream = File.OpenRead(sourcePath))
                fileStream.CopyTo(entryStream);

            addedNames.Add(entryName);
        }

        private static string GetUniqueName(string entryName, HashSet<string> added)
        {
            string unique = entryName;
            int i = 1;
            while (added.Contains(unique))
                unique = $"{Path.GetFileNameWithoutExtension(entryName)}_{i++}{Path.GetExtension(entryName)}";
            return unique;
        }

        private static bool IsImageFile(string path)
        {
            string[] exts = { ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff" };
            return exts.Contains(Path.GetExtension(path).ToLower());
        }


        public static string ReturnWhere(string search)
        {
            var searchWhere = new StringBuilder("1=1");

            if (string.IsNullOrWhiteSpace(search))
                return searchWhere.ToString();

            var searchFilters = search.Split('|', StringSplitOptions.RemoveEmptyEntries);

            foreach (var filter in searchFilters)
            {
                var parts = filter.Split('~', StringSplitOptions.RemoveEmptyEntries);

                if (parts.Length != 2)
                    continue;

                string fieldName = parts[0].Trim();
                string fieldValue = parts[1].Trim();

                if (string.IsNullOrEmpty(fieldName) || string.IsNullOrEmpty(fieldValue))
                    continue;
                //Changed On 16092025 
                //switch (fieldName)
                //{
                //    case "VIS_ENTRY_DATE":
                //    case "CONT_ADDED_DATETIME":
                //    case "LTR_SUBMITD_DATE":
                //    case "ADDED_DATE":
                //        searchWhere.AppendFormat(" AND CONVERT(VARCHAR, {0}, 105) LIKE '{1}%'", fieldName, EscapeSqlLike(fieldValue));
                //        break;

                //    case "VIS_MOBNO":
                //        searchWhere.AppendFormat(" AND (VIS_MOBNO LIKE '{0}%' OR VIS_ALTR_MOBNO LIKE '{0}%')", EscapeSqlLike(fieldValue));
                //        break;

                //    default:
                //        searchWhere.AppendFormat(" AND {0} LIKE N'%{1}%'", fieldName, EscapeSqlLike(fieldValue));
                //        break;
                //}

                switch (fieldName)
                {
                    case "VIS_ENTRY_DATE":
                    case "CONT_ADDED_DATETIME":
                    case "LTR_SUBMITD_DATE":
                    case "ADDED_DATE":
                        searchWhere.AppendFormat(" AND CONVERT(VARCHAR, {0}, 105) LIKE '{1}%'", fieldName, EscapeSqlLike(fieldValue));
                        break;
                    case "VIS_MOBNO":
                        if (fieldValue.Equals("HASDATA",StringComparison.OrdinalIgnoreCase))
                        {
                            searchWhere.AppendFormat(" AND ((VIS_MOBNO IS NOT NULL AND LTRIM(RTRIM(VIS_MOBNO))<>'') " +
                                "OR (VIS_ALTR_MOBNO IS NOT NULL AND LTRIM(RTRIM(VIS_ALTR_MOBNO)) <> ''))");
                                
                        }
                        else if (fieldValue.Equals("NODATA", StringComparison.OrdinalIgnoreCase))
                        {
                            searchWhere.Append(" AND ((VIS_MOBNO IS NULL OR LTRIM(RTRIM(VIS_MOBNO)) = '') " +
                                      "AND (VIS_ALTR_MOBNO IS NULL OR LTRIM(RTRIM(VIS_ALTR_MOBNO)) = ''))");
                        }
                        else
                        {
                              searchWhere.AppendFormat(
                                        " AND (VIS_MOBNO LIKE '%{0}%' OR VIS_ALTR_MOBNO LIKE '%{0}%')",
                               EscapeSqlLike(fieldValue)
                               );
                        }
                        break;

                    default:
                        switch(fieldValue.ToUpper())
                        {
                            case "HASDATA":
                                searchWhere.AppendFormat(" AND ({0} IS NOT NULL AND LTRIM(RTRIM({0})) <> '')", fieldName);
                                break;
                            case "NODATA":
                                searchWhere.AppendFormat(" AND ({0} IS NULL OR LTRIM(RTRIM({0})) = '')", fieldName);
                                break;

                            default:
                                searchWhere.AppendFormat(
                                    " AND {0} LIKE N'%{1}%'",
                                    fieldName,
                                    EscapeSqlLike(fieldValue)
                                );
                                break;
                        }
                        break;

                }
            }

            return searchWhere.ToString();
        }

        // Optional: Escapes special LIKE characters to prevent injection
        private static string EscapeSqlLike(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            return input.Replace("[", "[[]")
                        .Replace("%", "[%]")
                        .Replace("_", "[_]")
                        .Replace("'", "''");
        }

    }
}
