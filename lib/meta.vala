namespace Seafile {

public class Meta : Object {

    // _id is for fast access from c code. id is for
	// vala to automatically generate a property. Note,
	// if a Vala property is start with _, it is not
	// translated into a GObject property.
	public char _id[41];
	public string id {
		get { return (string)_id; }
		set { Posix.memcpy(_id, id, 40); _id[40] = '\0'; }
	}

	public string _name;
	public string name {
		get { return _name; }
		set { _name = name; }
	}

	public string _desc;		// description
	public string desc {
		get { return _desc; }
		set { _desc = value; }
	}

	public uint64 _ctime;
	public uint64 ctime {
		get { return _ctime; }
		set { _ctime = value; }
	}

}

} // namespace