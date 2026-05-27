using ClosedXML.Excel;
using System.Data;
using System.Globalization;
using System.IO.Compression;
// New Helper Created , Present Not Using ...
namespace Jabalpur_Office.Helpers
{
    public static class NewZipHelper
    {
        // =========================================================
        // 500 MB LIMIT
        // =========================================================

        private const long MAX_ZIP_SIZE =
            500L * 1024L * 1024L;

        // =========================================================
        // CREATE SPLIT ZIP FILES
        // =========================================================

        public static List<string>
            CreateSplitZipFiles(
                string excelFilePath,
                List<string> filePaths,
                string outputFolder,
                string zipBaseName
            )
        {
            List<string> createdZipFiles =
                new();

            if (!Directory.Exists(outputFolder))
            {
                Directory.CreateDirectory(
                    outputFolder
                );
            }

            int partNo = 1;

            long currentZipSize = 0;

            FileStream? zipFs = null;

            ZipArchive? archive = null;

            HashSet<string> addedNames =
                new(
                    StringComparer.OrdinalIgnoreCase
                );

            try
            {
                // =================================================
                // CREATE FIRST ZIP
                // =================================================

                CreateNewZip();

                // =================================================
                // ADD EXCEL FIRST
                // =================================================

                if (File.Exists(excelFilePath))
                {
                    FileInfo excelInfo =
                        new(excelFilePath);

                    AddFileToArchive(
                        archive!,
                        excelFilePath,
                        Path.GetFileName(
                            excelFilePath
                        ),
                        addedNames
                    );

                    currentZipSize +=
                        excelInfo.Length;
                }

                // =================================================
                // ADD ATTACHMENTS
                // =================================================

                foreach (string file in filePaths)
                {
                    try
                    {
                        if (!File.Exists(file))
                            continue;

                        FileInfo fi =
                            new(file);

                        long estimatedSize =
                            fi.Length;

                        // =========================================
                        // CREATE NEW ZIP IF LIMIT EXCEEDS
                        // =========================================

                        if (
                            currentZipSize
                            + estimatedSize
                            > MAX_ZIP_SIZE
                        )
                        {
                            archive?.Dispose();

                            zipFs?.Dispose();

                            partNo++;

                            currentZipSize = 0;

                            CreateNewZip();
                        }

                        string uniqueName =
                            GetUniqueName(
                                Path.GetFileName(file),
                                addedNames
                            );

                        AddFileToArchive(
                            archive!,
                            file,
                            uniqueName,
                            addedNames
                        );

                        currentZipSize +=
                            estimatedSize;
                    }
                    catch
                    {
                        // skip invalid file
                    }
                }
            }
            finally
            {
                archive?.Dispose();

                zipFs?.Dispose();
            }

            return createdZipFiles;

            // =====================================================
            // LOCAL FUNCTION
            // =====================================================

            void CreateNewZip()
            {
                string zipPath =
                    Path.Combine(
                        outputFolder,
                        $"{zipBaseName}" +
                        $"_Part{partNo}.zip"
                    );

                zipFs =
                    new FileStream(
                        zipPath,
                        FileMode.Create,
                        FileAccess.Write,
                        FileShare.None
                    );

                archive =
                    new ZipArchive(
                        zipFs,
                        ZipArchiveMode.Create
                    );

                createdZipFiles.Add(zipPath);
            }
        }

        // ========================================================
        // CREATE MONTH WISE ZIPS
        // ========================================================
        public static List<string>
        CreateMonthWiseSplitZipFiles(
            DataTable dt,
            List<DataColumn> fileColumns,
            string storageRoot,
            string basePath
        )
        {
            List<string> createdZipFiles = new();

            // ====================================================
            // GROUP BY MONTH
            // ====================================================

            var groupedMonths =
                dt.AsEnumerable()
                .GroupBy(row =>
                {
                    DateTime d =
                        Convert.ToDateTime(
                            row["DATE"]
                        );

                    return new
                    {
                        d.Year,
                        d.Month
                    };
                });

            // ====================================================
            // PROCESS EACH MONTH
            // ====================================================
            foreach (var monthGroup in groupedMonths)
            {
                string monthKey =
                $"{monthGroup.Key.Year}_" +
                $"{CultureInfo.InvariantCulture.DateTimeFormat.GetMonthName(monthGroup.Key.Month).ToUpper()}";

                string monthFolder =
                    Path.Combine(
                        basePath,
                        monthKey
                    );

                Directory.CreateDirectory(
                     monthFolder
                   );

                // =================================================
                // CREATE DATATABLE
                // =================================================

                DataTable monthTable = monthGroup.CopyToDataTable();

                DataTable excelTable = monthTable.Copy();

                // =================================================
                // REMOVE FILE COLUMNS
                // =================================================

                   var removeCols =
                   excelTable.Columns
                      .Cast<DataColumn>()
                      .Where(c =>
                          c.ColumnName
                          .ToUpper()
                          .Contains("FILE_PATH"))
                      .ToList();

                foreach (var col in removeCols)
                {
                    excelTable.Columns.Remove(col);
                }

                // =================================================
                // CREATE EXCEL
                // =================================================
                string excelFilePath = Path.Combine(monthFolder, $"{monthKey}.xlsx");

                using (var workbook = new XLWorkbook())
                {
                    var ws = workbook.Worksheets.Add(monthKey);

                    ws.Cell(1, 1)
                    .InsertTable(
                        excelTable,
                        $"TBL_{monthKey}",
                        true
                    );

                    workbook.SaveAs(
                         excelFilePath
                      );

                }

                // =================================================
                // COLLECT FILES
                // =================================================
                List<string> filePaths = new();
                foreach (DataRow row in monthTable.Rows)
                {
                    foreach (var col in fileColumns)
                    {

                        // CHECK COLUMN EXISTS
                        if (!monthTable.Columns.Contains(col.ColumnName))
                            continue;

                        string? rel = Convert.ToString(row[col.ColumnName])?.Trim();

                        if (string.IsNullOrEmpty(rel))
                            continue;

                        string fullPath = Path.Combine(storageRoot,
                                      rel.TrimStart('~', '/', '\\')
                                      .Replace("/", Path.DirectorySeparatorChar.ToString()));

                        if (File.Exists(fullPath))
                        {
                            filePaths.Add(fullPath);
                        }
                    }
                }

                // =================================================
                // CREATE SPLIT ZIPS
                // =================================================

                List<string> splitZips =
                    CreateSplitZipFiles(
                        excelFilePath,
                        filePaths,
                        monthFolder,
                        monthKey
                    );
                   
                createdZipFiles
                    .AddRange(splitZips);
            }
            return createdZipFiles;
        }




        

        // =========================================================
        // ADD FILE TO ZIP
        // =========================================================

        private static void AddFileToArchive(
            ZipArchive archive,
            string sourcePath,
            string entryName,
            HashSet<string> addedNames
        )
        {
            if (!File.Exists(sourcePath))
                return;

            var entry =
                archive.CreateEntry(
                    entryName,
                    CompressionLevel.Fastest
                );

            using Stream entryStream =
                entry.Open();

            using FileStream fileStream =
                new(
                    sourcePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read
                );

            fileStream.CopyTo(entryStream);
        }

        // =========================================================
        // UNIQUE FILE NAME
        // =========================================================

        private static string GetUniqueName(
            string fileName,
            HashSet<string> existing
        )
        {
            string name =
                Path.GetFileNameWithoutExtension(
                    fileName
                );

            string ext =
                Path.GetExtension(fileName);

            string finalName =
                fileName;

            int counter = 1;

            while (existing.Contains(finalName))
            {
                finalName =
                    $"{name}_{counter}{ext}";

                counter++;
            }

            existing.Add(finalName);

            return finalName;
        }
    }
}
