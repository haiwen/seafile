namespace Seafile {

public class File : Object {

    // _id is for fast access from c code. id is for
	// vala to automatically generate a property. Note,
	// if a Vala property is start with _, it is not
	// translated into a GObject property.
	public char _id[41];
	public string id {
		get { return (string)_id; }
		set { Posix.memcpy(_id, id, 40); _id[40] = '\0'; }
	}

	public uint64 size;
}

} // namespace