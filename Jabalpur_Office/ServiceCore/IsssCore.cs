using System.Data;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;

namespace Jabalpur_Office.ServiceCore
{
    public interface IsssCore
    {
        DataTable ExecProcDt(string procName, SqlParameter[] parameters);
        int ExecProcNonQuery(string procName, SqlParameter[] parameters);
        object ExecProcScalar(string procName, SqlParameter[] parameters);

        Task<object> ExecScalarAsync(string procName,  SqlParameter[] parameters);
        DataSet ExecProcDs(string procName, SqlParameter[] parameters); // ✅ Optional: include if used
        Task<int> ExecQryAsync(string queryText, SqlParameter[] parameters);

        int ExecNonQuery(string sql);

        object ExecScalarText(string procName, SqlParameter[] parameters);

        DataTable ExecProc(string procName);
        DataTable ExecDtText(string procName, SqlParameter[] parameters=null);
    }
}
