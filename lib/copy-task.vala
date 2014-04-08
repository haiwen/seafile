namespace Seafile {

public class CopyTask : Object {
       public int64 done { set; get; }
       public int64 total { set; get; }
       public bool canceled { set; get; }
       public bool failed { set; get; }
       public bool successful { set; get; }
}

public class CopyResult : Object {
       public bool background { set; get; }
       public string task_id { set; get; }
}

}
