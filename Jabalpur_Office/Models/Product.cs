namespace Jabalpur_Office.Models
{
    /// <summary>
    /// Base class for standard API response structure.
    /// </summary>
    public class Product
    {
        public int StatusCode { get; set; } = 500;
        public string Message { get; set; } = string.Empty;
        public string LoginStatus { get; set; } = string.Empty;
    }

    /// <summary>
    /// Wrapper for single object response with metadata.
    /// </summary>

    public class WrapperObjectData : Product, IHasDataObject
    {
        public object DataObject { get; set; }
    }

    public interface IHasDataObject
    {
        object DataObject { get; set; }
    }

    /// <summary>
    /// Wrapper for list-based response with optional paging.
    /// </summary>
    public class WrapperListData : Product, IHasDataList
    {
        public List<Dictionary<string, string>> DataList { get; set; }
        public Pager Pager { get; internal set; }
    }
    public interface IHasDataList
    {
        List<Dictionary<string, string>> DataList { get; set; }
    }

    /// <summary>
    /// Standard pagination input parameters.
    /// </summary>
    public class PaginationParams
    {
        public string Search { get; set; } = string.Empty;
        public int PageIndex { get; set; } = 1;
        public int PageSize { get; set; } = 100;
    }

    /// <summary>
    /// Wrapper for Create/Update (CRUD) response with ID return.
    /// </summary>
    public class WrapperCrudObjectData : Product
    {
        //public object DataObject { get; set; }
        public int RetID { get; set; }  // ← Add this line
    }

    /// <summary>
    /// Paging response metadata for UI and navigation.
    /// </summary>
    public class Pager
    {
        public Pager() { }

        public Pager(int totalItems, int? page, int pageSize = 10)
        {
            var totalPages = (int)Math.Ceiling((decimal)totalItems / pageSize);
            var currentPage = page ?? 1;

            var startPage = currentPage - 5;
            var endPage = currentPage + 4;

            if (startPage <= 0)
            {
                endPage -= (startPage - 1);
                startPage = 1;
            }

            if (endPage > totalPages)
            {
                endPage = totalPages;

                if (endPage > 10)
                    startPage = endPage - 9;
            }

            TotalItems = totalItems;
            CurrentPage = currentPage;
            PageSize = pageSize;
            TotalPages = totalPages;
            StartPage = startPage;
            EndPage = endPage;
        }

        public int TotalItems { get; set; }
        public int CurrentPage { get; set; }
        public int PageSize { get; set; }
        public int TotalPages { get; set; }
        public int StartPage { get; set; }
        public int EndPage { get; set; }
    }
}
