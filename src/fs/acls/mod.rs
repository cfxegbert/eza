#![allow(non_camel_case_types)]

#[cfg(target_os = "macos")]
mod qualifier_cache;

use libc::{gid_t, ssize_t, uid_t};
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;

pub type acl_t = *mut c_void;
pub type acl_permset_t = *mut c_void;
pub type acl_entry_t = *mut c_void;
#[cfg(target_os = "macos")]
pub type acl_flagset_t = *mut c_void;
pub type acl_type_t = c_uint;
pub type acl_tag_t = c_uint;
pub type acl_perm_t = c_uint;
pub type acl_entry_id_t = c_int;
#[cfg(target_os = "macos")]
pub type acl_flag_t = c_uint;
#[cfg(target_os = "macos")]
pub type acl_permset_mask_t = u64;

#[cfg(target_os = "macos")]
pub type uuid_t = [u8; 16];
#[cfg(target_os = "macos")]
pub type id_t = u32;

mod constants {
    use super::{acl_entry_id_t, acl_perm_t};

    pub const ACL_READ_DATA: acl_perm_t = 1 << 1;
    pub const ACL_LIST_DIRECTORY: acl_perm_t = ACL_READ_DATA;
    pub const ACL_WRITE_DATA: acl_perm_t = 1 << 2;
    pub const ACL_ADD_FILE: acl_perm_t = ACL_WRITE_DATA;
    pub const ACL_EXECUTE: acl_perm_t = 1 << 3;
    pub const ACL_SEARCH: acl_perm_t = ACL_EXECUTE;
    pub const ACL_DELETE: acl_perm_t = 1 << 4;
    pub const ACL_APPEND_DATA: acl_perm_t = 1 << 5;
    pub const ACL_ADD_SUBDIRECTORY: acl_perm_t = ACL_APPEND_DATA;
    pub const ACL_DELETE_CHILD: acl_perm_t = 1 << 6;
    pub const ACL_READ_ATTRIBUTES: acl_perm_t = 1 << 7;
    pub const ACL_WRITE_ATTRIBUTES: acl_perm_t = 1 << 8;
    pub const ACL_READ_EXTATTRIBUTES: acl_perm_t = 1 << 9;
    pub const ACL_WRITE_EXTATTRIBUTES: acl_perm_t = 1 << 10;
    pub const ACL_READ_SECURITY: acl_perm_t = 1 << 11;
    pub const ACL_WRITE_SECURITY: acl_perm_t = 1 << 12;
    pub const ACL_CHANGE_OWNER: acl_perm_t = 1 << 13;
    pub const ACL_SYNCHRONIZE: acl_perm_t = 1 << 20;

    use super::acl_tag_t;

    pub const ACL_UNDEFINED_TAG: acl_tag_t = 0;
    pub const ACL_EXTENDED_ALLOW: acl_tag_t = 1;
    pub const ACL_EXTENDED_DENY: acl_tag_t = 2;

    use super::acl_type_t;

    pub const ACL_TYPE_EXTENDED: acl_type_t = 0x0000_0100;
    pub const ACL_TYPE_ACCESS: acl_type_t = 0x0000_0000;
    pub const ACL_TYPE_DEFAULT: acl_type_t = 0x0000_0001;

    use super::acl_flag_t;

    pub const ACL_FLAG_DEFER_INHERIT: acl_flag_t = 1 << 0;
    pub const ACL_FLAG_NO_INHERIT: acl_flag_t = 1 << 17;
    pub const ACL_ENTRY_INHERITED: acl_flag_t = 1 << 4;
    pub const ACL_ENTRY_FILE_INHERIT: acl_flag_t = 1 << 5;
    pub const ACL_ENTRY_DIRECTORY_INHERIT: acl_flag_t = 1 << 6;
    pub const ACL_ENTRY_LIMIT_INHERIT: acl_flag_t = 1 << 7;
    pub const ACL_ENTRY_ONLY_INHERIT: acl_flag_t = 1 << 8;

    pub const ACL_FIRST_ENTRY: acl_entry_id_t = 0;
    pub const ACL_NEXT_ENTRY: acl_entry_id_t = -1;
    pub const ACL_LAST_ENTRY: acl_entry_id_t = -2;
}

use self::constants::*;

// On Linux link to libacl
#[cfg_attr(target_os = "linux", link(name = "acl"))]
extern "C" {
    // 23.1.6.1 ACL Storage Management
    pub fn acl_dup(acl: acl_t) -> acl_t;
    pub fn acl_free(data: *mut c_void) -> c_int;

    // 23.1.6.2 (1) ACL Entry manipulation
    pub fn acl_get_entry(acl: acl_t, entry_id: acl_entry_id_t, entry: *mut acl_entry_t) -> c_int;
    #[cfg(target_os = "macos")]
    pub fn acl_get_perm_np(permset: acl_permset_t, perm: acl_perm_t) -> c_int;
    #[cfg(target_os = "macos")]
    pub fn acl_get_flag_np(flagset: acl_flagset_t, flag: acl_flag_t) -> c_int;
    #[cfg(target_os = "macos")]
    pub fn acl_get_flagset_np(entry: acl_entry_t, flagset: *mut acl_flagset_t) -> c_int;

    // 23.1.6.2 (2) Manipulate permissions within an ACL entry
    pub fn acl_get_permset(entry: acl_entry_t, permset: *mut acl_permset_t) -> c_int;

    // 23.1.6.2 (3) Manipulate ACL entry tag type and qualifier
    pub fn acl_get_qualifier(entry: acl_entry_t) -> *mut c_void;
    pub fn acl_get_tag_type(entry: acl_entry_t, tag_type: *const acl_tag_t) -> c_int;

    // 23.1.6.3 ACL manipulation on an Object
    pub fn acl_get_file(path: *const c_char, typ: acl_type_t) -> acl_t;
    #[cfg(target_os = "macos")]
    pub fn acl_get_link_np(path: *const c_char, typ: acl_type_t) -> acl_t;

    // 23.1.6.4 ACL Format translation
    pub fn acl_size(acl: acl_t) -> ssize_t;
    pub fn acl_to_text(acl: acl_t, len: *mut ssize_t) -> *mut c_char;
}

struct AclFree<T> {
    ptr: *mut T,
}

impl<T> Drop for AclFree<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // Ignore return value from acl_free
            unsafe {
                acl_free(self.ptr.cast::<c_void>());
            }
        }
    }
}

#[derive(Clone)]
pub enum UserGroup {
    User(uid_t),
    Group(gid_t),
    Unknown(String),
}

fn format_string<T, F>(strings: &[(T, &str)], common_strings: &[(T, &str)], filter: F) -> String
where
    T: Copy,
    F: Fn(T) -> bool,
{
    strings
        .iter()
        .chain(common_strings)
        .filter(|item| filter(item.0))
        .map(|item| item.1)
        .collect::<Vec<&str>>()
        .join(",")
}

struct PermSet<'entry> {
    perm_set: acl_permset_t,
    is_directory: bool,
    _covariant: PhantomData<&'entry ()>,
}

type PermissionString = (acl_perm_t, &'static str);

impl<'entry> PermSet<'entry> {
    const FILE_PERMISSION_STRINGS: &'static [PermissionString] = &[
        (ACL_READ_DATA, "read"),
        (ACL_WRITE_DATA, "write"),
        (ACL_EXECUTE, "execute"),
        (ACL_APPEND_DATA, "append"),
    ];

    const DIR_PERMISSION_STRINGS: &'static [PermissionString] = &[
        (ACL_LIST_DIRECTORY, "list"),
        (ACL_ADD_FILE, "add_file"),
        (ACL_SEARCH, "search"),
        (ACL_ADD_SUBDIRECTORY, "add_subdirectory"),
        (ACL_DELETE_CHILD, "delete_child"),
    ];

    const COMMON_PERMISSION_STRINGS: &'static [PermissionString] = &[
        (ACL_DELETE, "delete"),
        (ACL_READ_ATTRIBUTES, "readattr"),
        (ACL_WRITE_ATTRIBUTES, "writeattr"),
        (ACL_READ_EXTATTRIBUTES, "readextattr"),
        (ACL_WRITE_EXTATTRIBUTES, "writeextattr"),
        (ACL_READ_SECURITY, "readsecurity"),
        (ACL_WRITE_SECURITY, "writesecurity"),
        (ACL_CHANGE_OWNER, "chown"),
    ];

    pub fn get(entry: &'entry acl_entry_t, is_directory: bool) -> Option<PermSet<'entry>> {
        let mut perm_set: acl_permset_t = ptr::null_mut();
        match unsafe { acl_get_permset(*entry, &mut perm_set) } {
            0 => Some(PermSet {
                perm_set,
                is_directory,
                _covariant: PhantomData,
            }),
            _ => None,
        }
    }

    fn has_permission(&self, perm: acl_perm_t) -> bool {
        unsafe { acl_get_perm_np(self.perm_set, perm) == 1 }
    }
}

impl<'entry> ToString for PermSet<'entry> {
    fn to_string(&self) -> String {
        let permission_strings = if self.is_directory {
            PermSet::DIR_PERMISSION_STRINGS
        } else {
            PermSet::FILE_PERMISSION_STRINGS
        };
        format_string(
            permission_strings,
            PermSet::COMMON_PERMISSION_STRINGS,
            |p| self.has_permission(p),
        )
    }
}

struct FlagSet<'entry> {
    flag_set: acl_flagset_t,
    is_directory: bool,
    _covariant: PhantomData<&'entry ()>,
}

type FlagString = (acl_flag_t, &'static str);

impl<'entry> FlagSet<'entry> {
    pub(super) const DIR_FLAG_STRINGS: &'static [FlagString] = &[
        (ACL_ENTRY_FILE_INHERIT, "file_inherit"),
        (ACL_ENTRY_DIRECTORY_INHERIT, "directory_inherit"),
        (ACL_ENTRY_ONLY_INHERIT, "only_inherit"),
    ];

    pub(super) const COMMON_FLAG_STRINGS: &'static [FlagString] =
        &[(ACL_ENTRY_LIMIT_INHERIT, "limit_inherit")];

    pub fn get(entry: &'entry acl_entry_t, is_directory: bool) -> Option<FlagSet<'entry>> {
        let mut flag_set: acl_flagset_t = ptr::null_mut();
        match unsafe { acl_get_flagset_np(*entry, &mut flag_set) } {
            0 => Some(FlagSet {
                flag_set,
                is_directory,
                _covariant: PhantomData,
            }),
            _ => None,
        }
    }

    fn has_flag(&self, flag: acl_flag_t) -> bool {
        unsafe { acl_get_flag_np(self.flag_set, flag) == 1 }
    }

    pub fn is_inherited(&self) -> bool {
        unsafe { acl_get_flag_np(self.flag_set, ACL_ENTRY_INHERITED) == 1 }
    }
}

impl<'entry> ToString for FlagSet<'entry> {
    fn to_string(&self) -> String {
        let flag_strings = if self.is_directory {
            FlagSet::DIR_FLAG_STRINGS
        } else {
            &[]
        };
        format_string(flag_strings, FlagSet::COMMON_FLAG_STRINGS, |f| {
            self.has_flag(f)
        })
    }
}

struct Tag<'entry> {
    tag: acl_tag_t,
    _covariant: PhantomData<&'entry ()>,
}

impl<'entry> Tag<'entry> {
    pub fn get(entry: &'entry acl_entry_t) -> Option<Tag<'entry>> {
        let mut tag: acl_tag_t = ACL_EXTENDED_ALLOW;
        match unsafe { acl_get_tag_type(*entry, &mut tag) } {
            0 => Some(Tag {
                tag,
                _covariant: PhantomData,
            }),
            _ => None,
        }
    }

    fn tag_str(&self) -> &'static str {
        match self.tag {
            ACL_EXTENDED_ALLOW => "allow",
            ACL_EXTENDED_DENY => "deny",
            _ => "unknown",
        }
    }
}

impl<'entry> ToString for Tag<'entry> {
    fn to_string(&self) -> String {
        self.tag_str().to_string()
    }
}

struct Qualifier {
    qualifier: AclFree<uuid_t>,
}

impl Qualifier {
    pub fn get(entry: &acl_entry_t) -> Option<Qualifier> {
        let qualifier = unsafe { acl_get_qualifier(*entry) };
        if qualifier.is_null() {
            None
        } else {
            Some(Qualifier {
                qualifier: AclFree {
                    ptr: qualifier.cast(),
                },
            })
        }
    }

    pub fn to_numeric_string(&self) -> String {
        match qualifier_cache::lookup_qualifier(self) {
            UserGroup::User(uid) => format!("user:{uid}"),
            UserGroup::Group(gid) => format!("group:{gid}"),
            UserGroup::Unknown(v) => v,
        }
    }
}

impl ToString for Qualifier {
    fn to_string(&self) -> String {
        match qualifier_cache::lookup_qualifier(self) {
            UserGroup::User(uid) => {
                if let Some(user) = uzers::get_user_by_uid(uid) {
                    format!("user:{}", user.name().to_string_lossy().to_string())
                } else {
                    format!("user:{uid}")
                }
            }
            UserGroup::Group(gid) => {
                if let Some(group) = uzers::get_group_by_gid(gid) {
                    format!("group:{}", group.name().to_string_lossy().to_string())
                } else {
                    format!("group:{gid}")
                }
            }
            UserGroup::Unknown(v) => v,
        }
    }
}

struct Entry<'entry> {
    index: i32,
    tag: Tag<'entry>,
    flag_set: FlagSet<'entry>,
    perm_set: PermSet<'entry>,
    qualifier: Qualifier,
}

impl<'entry> Entry<'entry> {
    fn new(entry: &'entry acl_entry_t, is_directory: bool, index: i32) -> Option<Entry<'entry>> {
        if let Some(tag) = Tag::get(entry) {
            if let Some(flag_set) = FlagSet::get(entry, is_directory) {
                if let Some(perm_set) = PermSet::get(entry, is_directory) {
                    if let Some(qualifier) = Qualifier::get(entry) {
                        return Some(Entry {
                            index,
                            tag,
                            flag_set,
                            perm_set,
                            qualifier,
                        });
                    }
                }
            }
        }
        None
    }

    fn format(&self, numeric_ids: bool) -> String {
        let id = if numeric_ids {
            self.qualifier.to_numeric_string()
        } else {
            self.qualifier.to_string()
        };
        let inherited = if self.flag_set.is_inherited() {
            " inherited"
        } else {
            ""
        };
        let tag = self.tag.tag_str();
        let perms = self.perm_set.to_string();
        let flags = self.flag_set.to_string();

        if flags.is_empty() {
            format!(
                "{index}: {id}{inherited} {tag} {perms}",
                index = self.index,
            )
        } else {
            format!(
                "{index}: {id}{inherited} {tag} {perms} {flags}",
                index = self.index,
            )
        }
    }
}
