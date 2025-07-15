using System.Data;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;

namespace Jabalpur_Office.ServiceCore
{
    public class sssCore : IsssCore
    {
        private readonly string _connectionString;

        public sssCore(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection");
        }

        public DataTable ExecProcDt(string procName, SqlParameter[] parameters)
        {
            using var conn = new SqlConnection(_connectionString);
            using var cmd = new SqlCommand(procName, conn) { CommandType = CommandType.StoredProcedure };
            if (parameters != null)
                cmd.Parameters.AddRange(parameters);
            var dt = new DataTable();
            new SqlDataAdapter(cmd).Fill(dt);
            return dt;
        }
        public int ExecProcNonQuery(string procName, SqlParameter[] parameters)
        {
            using var conn = new SqlConnection(_connectionString);
            using var cmd = new SqlCommand(procName, conn) { CommandType = CommandType.StoredProcedure };
            if (parameters != null)
                cmd.Parameters.AddRange(parameters);
            conn.Open();
            return cmd.ExecuteNonQuery();
        }

        public object ExecProcScalar(string procName, SqlParameter[] parameters)
        {
            using var conn = new SqlConnection(_connectionString);
            using var cmd = new SqlCommand(procName, conn) { CommandType = CommandType.StoredProcedure };
            if (parameters != null)
                cmd.Parameters.AddRange(parameters);
            conn.Open();
            return cmd.ExecuteScalar();
        }
    }
}
