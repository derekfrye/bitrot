//! Version-1 policy for supported and forward-compatible record types.

use crate::creator;
use crate::digest_page;
use crate::manifest;
use crate::record::Record;
use crate::recovery_chunk;
use crate::rolling_page;
use crate::superblock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Disposition {
    Known,
    UnknownRequired,
    UnknownOptional,
}

/// Classifies a record according to the types understood by whole-sidecar
/// assembly.
pub(super) const fn classify(record: &Record) -> Disposition {
    if is_known_type(record.record_type) {
        Disposition::Known
    } else if record.is_required() {
        Disposition::UnknownRequired
    } else {
        Disposition::UnknownOptional
    }
}

const fn is_known_type(record_type: u16) -> bool {
    matches!(
        record_type,
        superblock::RECORD_TYPE
            | manifest::RECORD_TYPE
            | digest_page::RECORD_TYPE
            | rolling_page::RECORD_TYPE
            | recovery_chunk::RECORD_TYPE
            | creator::RECORD_TYPE
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::FLAG_REQUIRED;

    fn record(record_type: u16, flags: u32) -> Record {
        Record {
            record_type,
            flags,
            protection_set_id: [0; 32],
            logical_id: 0,
            header_extension: Vec::new(),
            payload: Vec::new(),
        }
    }

    #[test]
    fn classifies_every_supported_type_as_known() {
        for record_type in [
            superblock::RECORD_TYPE,
            manifest::RECORD_TYPE,
            digest_page::RECORD_TYPE,
            rolling_page::RECORD_TYPE,
            recovery_chunk::RECORD_TYPE,
            creator::RECORD_TYPE,
        ] {
            assert_eq!(
                classify(&record(record_type, FLAG_REQUIRED)),
                Disposition::Known
            );
            assert_eq!(classify(&record(record_type, 0)), Disposition::Known);
        }
    }

    #[test]
    fn unknown_type_flags_control_forward_compatibility() {
        assert_eq!(
            classify(&record(99, FLAG_REQUIRED)),
            Disposition::UnknownRequired
        );
        assert_eq!(classify(&record(99, 0)), Disposition::UnknownOptional);
    }
}
