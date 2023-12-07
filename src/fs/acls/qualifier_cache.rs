use super::{id_t, uuid_t, Qualifier, UserGroup};
use dashmap::DashMap;
use std::ffi::{c_char, CStr};
use std::os::raw::{c_int, c_uchar};
use std::sync::OnceLock;

extern "C" {
    #[cfg(target_os = "macos")]
    fn mbr_uuid_to_id(uu: *const c_uchar, uid_or_gid: *mut id_t, id_type: *mut c_int) -> c_int;

    #[cfg(target_os = "macos")]
    fn uuid_unparse_upper(uu: *const c_uchar, out: *mut c_char);
}

const ID_TYPE_UID: c_int = 0;
const ID_TYPE_GID: c_int = 1;

static USER_GROUP_CACHE: OnceLock<DashMap<uuid_t, UserGroup>> = OnceLock::new();

fn to_uuid_string(uuid: &uuid_t) -> String {
    // A UUID contains 32 hex digits along with 4 “-” symbols, which makes
    // its length equal to 36 characters.  Add one character for the
    // trailing NULL
    let mut buffer: [c_char; 37] = [0; 37];
    unsafe {
        uuid_unparse_upper(uuid.as_ptr(), buffer.as_mut_ptr());
    }
    buffer[36] = 0; // Just to make sure we have a NULL
    unsafe {
        CStr::from_ptr(buffer.as_ptr())
            .to_string_lossy()
            .to_string()
    }
}

fn get_id_for_uuid(uuid: &uuid_t) -> UserGroup {
    let mut id_type: c_int = 0;
    let mut uid_or_gid: id_t = 0;

    let result = unsafe {
        mbr_uuid_to_id(
            uuid.as_ptr(),
            std::ptr::addr_of_mut!(uid_or_gid),
            std::ptr::addr_of_mut!(id_type),
        )
    };

    match (result, id_type) {
        (0, ID_TYPE_UID) => UserGroup::User(uid_or_gid),
        (0, ID_TYPE_GID) => UserGroup::Group(uid_or_gid),
        (_, _) => UserGroup::Unknown(to_uuid_string(uuid)),
    }
}

pub(super) fn lookup_qualifier(qualifier: &Qualifier) -> UserGroup {
    let uuid = unsafe { *qualifier.qualifier.ptr };
    USER_GROUP_CACHE
        .get_or_init(DashMap::new)
        .entry(uuid)
        .or_insert_with(|| get_id_for_uuid(&uuid))
        .value()
        .clone()
}
