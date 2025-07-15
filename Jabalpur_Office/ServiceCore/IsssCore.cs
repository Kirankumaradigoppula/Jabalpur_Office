using System.Data;
using Microsoft.Data.SqlClient;

namespace Jabalpur_Office.ServiceCore
{
    public interface IsssCore
    {
        DataTable ExecProcDt(string procName, SqlParameter[] parameters);
        int ExecProcNonQuery(string procName, SqlParameter[] parameters);
        object ExecProcScalar(string procName, SqlParameter[] parameters);
    }
}
