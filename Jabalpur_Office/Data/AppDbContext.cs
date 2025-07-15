using Microsoft.EntityFrameworkCore;
using Jabalpur_Office.Models;

namespace Jabalpur_Office.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<Product> Products { get; set; }
    }
}
