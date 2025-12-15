using System.Data.SqlClient;
using System.Collections.Generic;

public class VaultRepository
{
    private readonly string _connectionString = "Server=.;Database=SafeVault;Trusted_Connection=True;";

    // SECURE METHOD: Uses Parameterized Queries to prevent SQL Injection
    public List<string> GetSecretsSecurely(string categoryInput)
    {
        var secrets = new List<string>();

        using (SqlConnection conn = new SqlConnection(_connectionString))
        {
            // Fix: Using parameters (@Category) instead of string concatenation
            string query = "SELECT SecretValue FROM Vault WHERE Category = @Category";
            SqlCommand cmd = new SqlCommand(query, conn);
            
            // Input Validation: Ensure input is not null/empty before processing
            if (string.IsNullOrWhiteSpace(categoryInput)) return secrets;

            // Bind the parameter safely
            cmd.Parameters.AddWithValue("@Category", categoryInput);

            try
            {
                conn.Open();
                SqlDataReader reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    secrets.Add(reader["SecretValue"].ToString());
                }
            }
            catch (Exception ex)
            {
                // Log error securely (avoid exposing stack trace to user)
                Console.WriteLine("Database error occurred.");
            }
        }
        return secrets;
    }
}
