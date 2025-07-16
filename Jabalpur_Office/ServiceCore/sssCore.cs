using System;
using System.Data;
using System.Threading.Tasks;
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
            try
            {
                using var conn = new SqlConnection(_connectionString);
                using var cmd = new SqlCommand(procName, conn)
                {
                    CommandType = CommandType.StoredProcedure,
                    CommandTimeout = 120 // Optional: customize timeout
                };

                if (parameters != null)
                    cmd.Parameters.AddRange(parameters);

                var dt = new DataTable();
                using var adapter = new SqlDataAdapter(cmd);
                adapter.Fill(dt);
                return dt;
            }
            catch (Exception ex)
            {
                throw new Exception($"Error executing procedure '{procName}'", ex);
            }
        }
        public int ExecProcNonQuery(string procName, SqlParameter[] parameters)
        {
         

            try
            {
                using var conn = new SqlConnection(_connectionString);
                using var cmd = new SqlCommand(procName, conn)
                {
                    CommandType = CommandType.StoredProcedure,
                    CommandTimeout = 120
                };

                if (parameters != null)
                    cmd.Parameters.AddRange(parameters);

                conn.Open();
                return cmd.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                throw new Exception($"Error executing procedure '{procName}'", ex);
            }


        }

        public object ExecProcScalar(string procName, SqlParameter[] parameters)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                using var cmd = new SqlCommand(procName, conn)
                {
                    CommandType = CommandType.StoredProcedure,
                    CommandTimeout = 120
                };

                if (parameters != null)
                    cmd.Parameters.AddRange(parameters);

                conn.Open();
                return cmd.ExecuteScalar();
            }
            catch (Exception ex)
            {
                throw new Exception($"Error executing procedure '{procName}'", ex);
            }
        }

        public async Task<object> ExecScalarAsync(string procName,  SqlParameter[] parameters)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                using var cmd = new SqlCommand(procName, conn)
                {
                    CommandType = CommandType.StoredProcedure,
                    CommandTimeout = 120
                };

                if (parameters?.Length > 0)
                    cmd.Parameters.AddRange(parameters);

                await conn.OpenAsync();
                return await cmd.ExecuteScalarAsync();
            }
            catch (Exception ex)
            {
                throw new Exception($"Error executing async scalar for procedure '{procName}'", ex);
            }
        }

        public DataSet ExecProcDs(string procName, SqlParameter[] parameters)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                using var cmd = new SqlCommand(procName, conn)
                {
                    CommandType = CommandType.StoredProcedure,
                    CommandTimeout = 120
                };

                if (parameters != null)
                    cmd.Parameters.AddRange(parameters);

                var ds = new DataSet();
                using var adapter = new SqlDataAdapter(cmd);
                adapter.Fill(ds);
                return ds;
            }
            catch (Exception ex)
            {
                throw new Exception($"Error executing procedure '{procName}' to get DataSet", ex);
            }
        }

        public async Task<int> ExecQryAsync(string queryText, SqlParameter[] parameters)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                using var cmd = new SqlCommand(queryText, conn)
                {
                    CommandType = CommandType.Text,
                    CommandTimeout = 120
                };

                if (parameters?.Length > 0)
                    cmd.Parameters.AddRange(parameters);

                await conn.OpenAsync();
                return await cmd.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                throw new Exception($"Error executing query '{queryText}'", ex);
            }
        }



    }
}
