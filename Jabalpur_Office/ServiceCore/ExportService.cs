using ClosedXML.Excel;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using SkiaSharp;
using System.Data;
using System.Text;
using System.Net;
using Jabalpur_Office.Models;
using Microsoft.Extensions.Options;
using Microsoft.Reporting.WebForms;
using System.Security.Principal;
using static Jabalpur_Office.Controllers.ZipController;

namespace Jabalpur_Office.ServiceCore
{
    public class ExportService : IExportService
    {
        private readonly SsrsSettings _settings;

        public ExportService(IOptions<SsrsSettings> options)
        {
            _settings = options.Value;
            QuestPDF.Settings.License = LicenseType.Community;
        }
        public byte[] ExportFromDataTable(
            DataTable dt,
            string? exportType,
            string fileName,
            string title,
            List<ImagePdfItem> images,
            out string contentType
             //out string fileName
             )
        {
            exportType = exportType?.ToUpperInvariant();

            switch (exportType)
            {
                case "PDF":
                    contentType = "application/pdf";
                    fileName = $"Report_{fileName}.pdf";
                    return ExportPdf(dt, title);

                case "IMAGE_TO_PDF":
                    contentType = "application/pdf";
                    fileName = $"Report_{fileName}.pdf";
                    return ExportImageToPdf(images);

                case "EXCEL":
                case "XLSX":
                    contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
                    fileName = $"Report_{fileName}.xlxs";
                    return ExportExcel(dt, title);

                case "CSV":
                    contentType = "text/csv";
                    fileName = $"Report_{fileName}.csv";
                    return ExportCsv(dt);

                case "WORD":
                case "DOCX":
                    contentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
                    fileName = $"Report_{fileName}.docx";
                    return ExportWord(dt, title);

                default:
                    contentType = "application/pdf";
                    fileName = $"Report_{fileName}.pdf";
                    return ExportPdf(dt, title);

            }
        }

        // ---------------- csv ----------------
        private byte[] ExportCsv(DataTable dt)
        {
            var sb = new StringBuilder();

            // Header
            sb.AppendLine(string.Join(",", dt.Columns.Cast<DataColumn>()
                .Select(c => EscapeCsv(c.ColumnName))));

            // Rows
            foreach (DataRow row in dt.Rows)
            {
                sb.AppendLine(string.Join(",", row.ItemArray
                    .Select(v => EscapeCsv(v?.ToString() ?? ""))));
            }

            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        private static string EscapeCsv(string value)
        {
            if (value.Contains(",") || value.Contains("\"") || value.Contains("\n"))
            {
                value = value.Replace("\"", "\"\"");
                return $"\"{value}\"";
            }
            return value;
        }

        // ---------------- WORD ----------------
        private byte[] ExportWord(DataTable dt, string title)
        {
            using var ms = new MemoryStream();
            using var wordDoc = WordprocessingDocument.Create(
                ms,
                WordprocessingDocumentType.Document,
                true
            );

            var mainPart = wordDoc.AddMainDocumentPart();
            mainPart.Document = new DocumentFormat.OpenXml.Wordprocessing.Document(new Body());

            var body = mainPart.Document.Body;

            // 🔹 Title
            body?.AppendChild(new Paragraph(
                new Run(
                    new Text(title)
                )
            )
            {
                ParagraphProperties = new ParagraphProperties(
                    new Justification { Val = JustificationValues.Center }
                )
            });

            // 🔹 Table
            var table = new Table();

            table.AppendChild(new TableProperties(
                new TableBorders(
                    new TopBorder { Val = BorderValues.Single, Size = 6 },
                    new BottomBorder { Val = BorderValues.Single, Size = 6 },
                    new LeftBorder { Val = BorderValues.Single, Size = 6 },
                    new RightBorder { Val = BorderValues.Single, Size = 6 },
                    new InsideHorizontalBorder { Val = BorderValues.Single, Size = 6 },
                    new InsideVerticalBorder { Val = BorderValues.Single, Size = 6 }
                )
            ));

            // Header row
            var headerRow = new TableRow();
            foreach (DataColumn col in dt.Columns)
            {
                headerRow.Append(CreateWordCell(col.ColumnName, true));
            }
            table.Append(headerRow);

            // Data rows
            foreach (DataRow row in dt.Rows)
            {
                var dataRow = new TableRow();
                foreach (var cell in row.ItemArray)
                {
                    dataRow.Append(CreateWordCell(cell?.ToString() ?? "", false));
                }
                table.Append(dataRow);
            }

            body?.Append(table);
            mainPart.Document.Save();

            return ms.ToArray();
        }

        private static TableCell CreateWordCell(string text, bool isHeader)
        {
            return new TableCell(
                new Paragraph(
                    new Run(
                        new Text(text)
                    )
                )
            )
            {
                TableCellProperties = new TableCellProperties(
                    new TableCellWidth { Type = TableWidthUnitValues.Auto }
                )
            };
        }

        // ---------------- PDF ----------------
        private byte[] ExportPdf(DataTable dt, string title)
        {

            return QuestPDF.Fluent.Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Size(PageSizes.A4.Landscape());
                    page.Margin(15);

                    // ===== WATERMARK =====
                    page.Background().Element(bg =>
                    {
                        bg.AlignCenter()
                          .AlignMiddle()
                          .Rotate(-30)
                          .Text("BJP")
                          .FontSize(80)
                          .Bold()
                          .FontColor(Colors.Grey.Lighten3);
                    });

                    // ===== HEADER =====
                    page.Header()
                        .AlignCenter()
                        .Text(title)
                        .FontSize(14)
                        .Bold();

                    page.Content().PaddingTop(10).Table(table =>
                    {
                        int colCount = dt.Columns.Count;
                        int mobileColIndex = dt.Columns.IndexOf("Mobile");

                        // ===== COLUMN DEFINITIONS =====
                        table.ColumnsDefinition(cols =>
                        {
                            for (int i = 0; i < colCount; i++)
                            {
                                if (i == 0)
                                    cols.ConstantColumn(30);          // 👈 First column small
                                else if (i == mobileColIndex)
                                    cols.ConstantColumn(80);         // 👈 Mobile inline
                                else
                                    cols.RelativeColumn();
                            }
                        });

                        // ===== TABLE HEADER =====
                        table.Header(header =>
                        {
                            foreach (DataColumn col in dt.Columns)
                            {
                                header.Cell()
                                      .Border(1)
                                      .BorderColor(Colors.Black)
                                      .Background(Colors.Grey.Lighten2)
                                      .Padding(4)
                                      .AlignCenter()
                                      .Text(col.ColumnName)
                                      .FontSize(9)
                                      .Bold();
                            }
                        });

                        // ===== TABLE ROWS =====
                        bool isEven = true;

                        foreach (DataRow row in dt.Rows)
                        {
                            for (int col = 0; col < colCount; col++)
                            {
                                var cell = table.Cell()
                                    .Border(1)
                                    .BorderColor(Colors.Black)
                                    .Background(isEven ? Colors.White : Colors.Grey.Lighten4)
                                    .Padding(3);

                                if (col == mobileColIndex)
                                {
                                    cell.AlignCenter()
                                        .Text(row[col]?.ToString() ?? "")
                                        .FontSize(8);
                                }
                                else
                                {
                                    cell.Text(row[col]?.ToString() ?? "")
                                        .FontSize(8);
                                }
                            }

                            isEven = !isEven;
                        }
                    });

                    // ===== FOOTER =====
                    page.Footer()
                        .AlignRight()
                        .Text(x =>
                        {
                            x.Span("Page ");
                            x.CurrentPageNumber();
                            x.Span(" of ");
                            x.TotalPages();
                        });
                });
            }).GeneratePdf();


        }

        // ---------------- IMAGE_TO_PDF ----------------
        private byte[] ExportImageToPdf(List<ImagePdfItem> images)
        {
            return QuestPDF.Fluent.Document.Create(container =>
            {
                foreach (var item in images)
                {
                    //var imageSize = ImageSize.FromBinary(item.ImageBytes);
                    var (imgWidth, imgHeight) = GetImageSize(item.ImageBytes);
                    // Extra space for title + margins
                    //float pageWidth = imgWidth + 40;
                    //float pageHeight = imgHeight + 100; // title space

                    container.Page(page =>
                    {
                        //page.Size(PageSizes.A4);
                        //page.Margin(20);

                        // ===== PAGE SIZE BASED ON IMAGE =====
                        page.Size(imgWidth + 40, imgHeight + 100, Unit.Point);
                        page.Margin(20);

                        // ===== TITLE =====
                        // page.Header()
                        //     .PaddingBottom(10)
                        //     .AlignCenter()
                        //     .Text(item.Title ?? "Image")
                        //     .FontSize(16)
                        //     .Bold();

                        // ===== IMAGE =====
                        page.Content()
                            .AlignCenter()
                            .AlignMiddle()
                            .Image(item.ImageBytes, ImageScaling.FitArea);
                        //  .Image(item.ImageBytes, ImageScaling.FitArea);

                        // ===== FOOTER =====
                        page.Footer().Row(row =>
                        {
                            //row.RelativeItem().AlignLeft().Text(""); // empty left space
                            row.RelativeItem().AlignLeft().Text(text =>
                            {
                                text.Span(item.Title ?? "Image")
                                 .FontSize(40)
                                 .Style(TextStyle.Default.Bold())
                                 .FontColor(Colors.Blue.Lighten1);

                            });
                            //row.RelativeItem().AlignRight().Text(text =>
                            //{
                            //    text.Span("Page ");
                            //    text.CurrentPageNumber();
                            //    text.Span(" of ");
                            //    text.TotalPages();
                            //});


                        });
                        //page.Footer()
                        //    .AlignRight()
                        //    .Text(x =>
                        //    {
                        //        x.Span("Page ");
                        //        x.CurrentPageNumber();
                        //        x.Span(" of ");
                        //        x.TotalPages();
                        //    });
                    });
                }
            }).GeneratePdf();
        }

        private static (float Width, float Height) GetImageSize(byte[] imageBytes)
        {
            using var ms = new MemoryStream(imageBytes);
            using var bitmap = SKBitmap.Decode(ms);

            if (bitmap == null)
                throw new Exception("Invalid image data");

            // float dpiX = bitmap.Info.DpiX > 0 ? bitmap.Info.DpiX : 72;
            // float dpiY = bitmap.Info.DpiY > 0 ? bitmap.Info.DpiY : 72;
            //
            // float width = bitmap.Width * 72f / dpiX;
            // float height = bitmap.Height * 72f / dpiY;

            // SkiaSharp gives pixel size only
            // Assume 72 DPI for PDF (standard)
            float width = bitmap.Width;
            float height = bitmap.Height;

            return (width, height);
        }


        // ---------------- EXCEL ----------------
        private byte[] ExportExcel(DataTable dt, string title)
        {
            using var wb = new XLWorkbook();
            var ws = wb.Worksheets.Add("Report");



            int titleRow = 1;

            // 🔹 1. TABLE TITLE
            ws.Cell(titleRow, 1).Value = title;
            ws.Range(titleRow, 1, titleRow, dt.Columns.Count).Merge();
            ws.Cell(titleRow, 1).Style.Font.Bold = true;
            ws.Cell(titleRow, 1).Style.Font.FontSize = 16;
            ws.Cell(titleRow, 1).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
            ws.Cell(titleRow, 1).Style.Alignment.Vertical = XLAlignmentVerticalValues.Center;
            ws.Row(titleRow).Height = 30;

            // 🔹 2. INSERT TABLE (START FROM ROW 3)
            int tableStartRow = titleRow + 1;

            var table = ws.Cell(tableStartRow, 1).InsertTable(dt, true);

            // 🔹 3. HEADER STYLE
            table.Theme = XLTableTheme.TableStyleMedium9;
            table.ShowAutoFilter = true;

            // 🔹 4. BORDER FOR ENTIRE TABLE
            var tableRange = table.RangeUsed();

            tableRange.Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
            tableRange.Style.Border.InsideBorder = XLBorderStyleValues.Thin;

            // 🔹 5. AUTO FIT
            ws.Columns().AdjustToContents();

            using var ms = new MemoryStream();
            wb.SaveAs(ms);
            return ms.ToArray();

        }

        public byte[] ExportSsrs(string reportName, string format, ReportParameter[] parameters)
        {
            var viewer = new ReportViewer
            {
                ProcessingMode = ProcessingMode.Remote
            };

            viewer.ServerReport.ReportServerUrl =
                new Uri(_settings.ReportServerUrl);

            viewer.ServerReport.ReportPath =
                $"{_settings.ReportPath}/{reportName}";

            viewer.ServerReport.ReportServerCredentials =
                new SsrsReportCredentials(_settings);

            if (parameters?.Length > 0)
                viewer.ServerReport.SetParameters(parameters);

            return viewer.ServerReport.Render(
                format,
                null,
                out string mimeType,
                out _,
                out _,
                out _,
                out _
            );
        }

        public class SsrsReportCredentials : IReportServerCredentials
        {
            private readonly SsrsSettings _settings;
            public SsrsReportCredentials(SsrsSettings settings)
            {
                _settings = settings;
            }
            public WindowsIdentity? ImpersonationUser => null;
            public ICredentials NetworkCredentials =>
           new NetworkCredential(
               _settings.Username,
               _settings.Password,
               _settings.Domain);

            public bool GetFormsCredentials(
            out Cookie? authCookie,
            out string? user,
            out string? password,
            out string? authority)
            {
                authCookie = null;
                user = password = authority = null;
                return false;
            }
        }
    }
}
