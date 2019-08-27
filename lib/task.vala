namespace Seafile {

public class Task : Object {

	public char _tx_id[37];
	public string tx_id {
		get { return (string)_tx_id; }
		set { Posix.memcpy(_tx_id, value, 36); _tx_id[36] = '\0'; }
	}

    public string ttype { get; set; }

	public string repo_id { get; set; }

	public string dest_id { get; set; }
	public string from_branch { get; set; }

	public string to_branch { get; set; }

	public string state { get; set; }

	public string rt_state { get; set; }

    public int64 block_total { get; set; }
    public int64 block_done { get; set; } // the number of blocks sent or received

    public int fs_objects_total { get; set; }
    public int fs_objects_done { get; set; }

	public int rate { get; set; }

	public int64 _rsize;		// the size remain
	public int64  rsize{
		get { return _rsize; }
		set { _rsize = value; }
	}

	public int64 _dsize;		// the size has done
	public int64 dsize {
		get { return _dsize; }
		set { _dsize = value; }
	}

}

public class CloneTask : Object {
       public string state { get; set; }
       public int error { get; set; }
       public string repo_id { get; set; }
       public string repo_name { get; set; }
       public string worktree { get; set; }
}

} // namespace
