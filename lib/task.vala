namespace Seafile {

public class Task : Object {

    public string ttype { get; set; }

	public string repo_id { get; set; }

	public string state { get; set; }

	public string rt_state { get; set; }

    public int64 block_total { get; set; }
    public int64 block_done { get; set; } // the number of blocks sent or received

    public int fs_objects_total { get; set; }
    public int fs_objects_done { get; set; }

	public int rate { get; set; }
}

public class CloneTask : Object {
       public string state { get; set; }
       public int error { get; set; }
       public string repo_id { get; set; }
       public string repo_name { get; set; }
       public string worktree { get; set; }
}

} // namespace
