// compile this file with `valac --pkg posix repo.vala -C -H repo.h`

namespace Seafile {

public class Branch : Object {

    public string _name;
    public string name {
        get { return _name; }
        set { _name = value; }
    }

    public string _commit_id;
    public string commit_id {
        get { return _commit_id; }
        set { _commit_id = value; }
    }

	public string _repo_id;
	public string repo_id {
		get { return _repo_id; }
		set { _repo_id = value; }
	}
}

} // namespace
