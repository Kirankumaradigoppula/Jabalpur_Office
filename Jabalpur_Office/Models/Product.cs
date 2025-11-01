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

        // Generic container for API-specific extra info
        public Dictionary<string, object> ExtraData { get; set; } = new();


        //public List<Dictionary<string, object>> DataObjectList { get; set; } = new List<Dictionary<string, object>>();
        public Pager Pager { get; internal set; }
    }
    public interface IHasDataList
    {
        List<Dictionary<string, string>> DataList { get; set; }
        //public List<Dictionary<string, object>> DataObjectList { get; set; }

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
        public int RetID { get; set; }  // ← Add this line
        // Generic container for API-specific extra info
        public Dictionary<string, object> ExtraData { get; set; } = new();
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

    public class StorageSettings
    {
        public string BasePath { get; set; }
    }

    public class MenuItem
    {
        public string ID { get; set; }
        public string MENU_RIGHT_ID { get; set; }
        public string MP_SEAT_ID { get; set; }
        public string USERID { get; set; }
        public string ROLE_ID { get; set; }
        public string MENU_MAS_ID { get; set; }
        public string MENUID { get; set; }
        public string MENUNM { get; set; }
        public string MENUGROUP { get; set; }
        public string PARENTID { get; set; }
        public string PARENTMENU { get; set; }
        public bool STATUS { get; set; }
        public string PATH { get; set; }
        public string ICON { get; set; }
        public string ORD { get; set; }
        public string JS { get; set; }
        public int MENU_HAS_ACCESS { get; set; }
        public int C_USER_ACCESS { get; set; }
        public int U_USER_ACCESS { get; set; }
        public int D_USER_ACCESS { get; set; }
        public int LEVEL { get; set; }  // 1 = Menu, 2 = Child, 3 = SubChild
        public string HierarchyPath { get; set; }  // 1 = Menu, 2 = Child, 3 = SubChild
        public List<MenuItem> Children { get; set; } = new List<MenuItem>();

    }


    
}
