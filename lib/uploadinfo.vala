namespace Seafile {

public class UploadInfo : Object {

    // _id is for fast access from c code. id is for
	// vala to automatically generate a property. Note,
	// if a Vala property is start with _, it is not
	// translated into a GObject property.
	public char _repo_id[37];
	public string repo_id {
		get { return (string)_repo_id; }
		set { Posix.memcpy(_repo_id, value, 36); _repo_id[36] = '\0'; }
	}

	public char _commit_id[41];
	public string commit_id {
		get { return (string)_commit_id; }
		set { Posix.memcpy(_commit_id, value, 40); _commit_id[40] = '\0'; }
	}

	public char _user_id[41];
	public string user_id {
		get { return (string)_user_id; }
		set { Posix.memcpy(_user_id, value, 40); _user_id[40] = '\0'; }
	}

    public int _timestamp;
    public int timestamp {
		get { return _timestamp; }
		set { _timestamp = value; }
	}

}

} // namespace