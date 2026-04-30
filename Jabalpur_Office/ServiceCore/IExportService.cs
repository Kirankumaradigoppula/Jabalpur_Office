using static Jabalpur_Office.Controllers.ZipController;
using Microsoft.Reporting.WebForms;
using System.Data;

namespace Jabalpur_Office.ServiceCore
{
    public interface IExportService
    {
        byte[] ExportSsrs(string reportName, string format, ReportParameter[] parameters);

        byte[] ExportFromDataTable(DataTable dt, string exportType, string fileName, string title, List<ImagePdfItem> images, out string contentType);
    }
}
