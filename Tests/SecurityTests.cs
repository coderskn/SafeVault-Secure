using Xunit;

public class SecurityTests
{
    [Fact]
    public void GetSecrets_WithSQLInjectionAttempt_ShouldReturnEmptyOrSafeResult()
    {
        // Arrange
        var repo = new VaultRepository();
        // A common SQL injection attack string
        string maliciousInput = "' OR 1=1 --"; 

        // Act
        var result = repo.GetSecretsSecurely(maliciousInput);

        // Assert
        // If SQLi worked, this would return ALL secrets. 
        // Since it is secure, it should return 0 results (because no category matches "' OR 1=1 --")
        Assert.Empty(result); 
    }

    [Fact]
    public void GetSecrets_WithValidInput_ShouldReturnData()
    {
        // Arrange
        var repo = new VaultRepository();
        string validInput = "Finance";

        // Act
        var result = repo.GetSecretsSecurely(validInput);

        // Assert
        Assert.NotNull(result);
    }
}
