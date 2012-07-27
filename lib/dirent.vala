namespace Seafile {

public class Dirent : Object {

    // _id is for fast access from c code. id is for
	// vala to automatically generate a property. Note,
	// if a Vala property is start with _, it is not
	// translated into a GObject property.
	public string obj_id { set; get; }

	public string obj_name { set; get; }

	public int mode { set; get; }
}

} // namespace
