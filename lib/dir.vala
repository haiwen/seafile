namespace Seafile {

	public class Dir : Object {

		// _id is for fast access from c code. id is for
		// vala to automatically generate a property. Note,
		// if a Vala property is start with _, it is not
		// translated into a GObject property.
		public char _id[41];
		public string id {
			get { return (string)_id; }
			set { Posix.memcpy(_id, value, 40); _id[40] = '\0'; }
		}
		
		public List<Dirent> entries;
		public int version { set; get; }
	}

} // namespace
