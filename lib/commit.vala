// compile this file with `valac --pkg posix repo.vala -C -H repo.h`

namespace Seafile {

public class Commit : Object {

    // _id is for fast access from c code. id is for
	// vala to automatically generate a property. Note,
	// if a Vala property is start with _, it is not
	// translated into a GObject property.
	public char _id[41];
	public string id {
		get { return (string)_id; }
		set { Posix.memcpy(_id, value, 40); _id[40] = '\0'; }
	}

    public string creator_name { get; set; }

	public string _creator;     // creator
	public string creator {
		get { return _creator; }
		set { _creator = value; }
	}

	public string _desc;		// description: what does this commit change
	public string desc {
		get { return _desc; }
		set { _desc = value; }
	}

	public int64 _ctime;		// create time
	public int64 ctime {
		get { return _ctime; }
		set { _ctime = value; }
	}

	public string parent_id { get; set;}

	public string second_parent_id { get; set; }

	public string _repo_id;
	public string repo_id {
		get { return _repo_id; }
		set { _repo_id = value; }
	}


	// A commit point to a file or dir, not both.

	public string _root_id;
	public string root_id {
		get { return _root_id; }
		set { _root_id = value; }
	}

	// Repo data-format version of this commit
	public int version { get; set; }
	public bool new_merge { get; set; }
	public bool conflict { get; set; }

	// Used for returning file revision
	public string rev_file_id { get; set; }
	public int64 rev_file_size { get; set; }
	// Set if this commit renames a revision of a file
	public string rev_renamed_old_path { get; set; }

	public string device_name { get; set; }
}

} // namespace
