using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;

[ApiController]
[Route("api/[controller]")]
public class VaultController : ControllerBase
{
    private readonly VaultRepository _repo = new VaultRepository();

    // REQUIREMENT: Role-Based Access Control (Only Admins can access)
    [Authorize(Roles = "Admin")] 
    [HttpGet("secrets")]
    public IActionResult GetSecrets([FromQuery] string category)
    {
        // REQUIREMENT: Input Validation
        if (!System.Text.RegularExpressions.Regex.IsMatch(category, "^[a-zA-Z0-9]*$"))
        {
            return BadRequest("Invalid input format.");
        }

        var data = _repo.GetSecretsSecurely(category);
        
        // REQUIREMENT: Prevent XSS by encoding output
        var safeData = data.Select(d => HtmlEncoder.Default.Encode(d)).ToList();

        return Ok(safeData);
    }
}
