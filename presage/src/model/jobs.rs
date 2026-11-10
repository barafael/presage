//! Work presage owes after a message, kept in the store until done.

use serde::{Deserialize, Serialize};

/// What presage still has to do for something it received: the store keeps it
/// ([`ContentsStore::enqueue_job`]) until it is done, so that a failure, or the process
/// ending, puts it off instead of losing it. Run while receiving.
///
/// [`ContentsStore::enqueue_job`]: crate::store::ContentsStore::enqueue_job
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Job {
    /// Fetch the profile of a sender seen first, or with a new profile key, and save them as a
    /// contact.
    FetchProfile {
        aci: [u8; 16],
        profile_key: [u8; 32],
        expire_timer: u32,
        expire_timer_version: u32,
    },
    /// Bring a group up to `revision`, which a message showed and reading it then failed.
    UpdateGroup { master_key: [u8; 32], revision: u32 },
    /// Download a sticker pack installed on another device.
    InstallStickerPack { pack_id: Vec<u8>, pack_key: Vec<u8> },
    /// Read the groups the storage service lists.
    SyncStorage,
    /// Save the contacts another device sent: `contacts` is its `SyncMessage.Contacts`.
    SaveContacts { contacts: Vec<u8> },
    /// Send our contacts to a device of ours that asked.
    AnswerContacts,
    /// Send the account's keys to a device of ours that asked.
    AnswerKeys,
    /// Ask the primary device for the account's keys.
    RequestKeys,
}

impl Job {
    /// One job waits per key: queued again, it takes the place of the one waiting.
    pub fn key(&self) -> String {
        match self {
            Self::FetchProfile { aci, .. } => format!("profile:{}", hex::encode(aci)),
            Self::UpdateGroup { master_key, .. } => format!("group:{}", hex::encode(master_key)),
            Self::InstallStickerPack { pack_id, .. } => {
                format!("sticker-pack:{}", hex::encode(pack_id))
            }
            Self::SyncStorage => "storage".into(),
            Self::SaveContacts { .. } => "contacts".into(),
            Self::AnswerContacts => "answer:contacts".into(),
            Self::AnswerKeys => "answer:keys".into(),
            Self::RequestKeys => "request:keys".into(),
        }
    }
}

/// A [`Job`] as the store keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedJob {
    pub id: u64,
    pub job: Job,
    /// How often it failed.
    pub attempts: u32,
    /// Not before this time, in milliseconds since the epoch.
    pub due_at: u64,
}

const WAITS_SECS: [u64; 6] = [5, 30, 120, 600, 3600, 6 * 3600];

/// How long after failing `attempts` times a job waits, or `None` once it is given up. A
/// failure of the connection (`connection_failed`) says nothing against the job: it waits, the
/// longest wait at most, and isn't given up.
pub fn backoff(attempts: u32, connection_failed: bool) -> Option<std::time::Duration> {
    let wait = WAITS_SECS.get(attempts.checked_sub(1)? as usize).copied();
    wait.or(connection_failed.then_some(WAITS_SECS[WAITS_SECS.len() - 1]))
        .map(std::time::Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::{backoff, Job};

    #[test]
    fn one_job_per_subject() {
        let fetch = |profile_key| Job::FetchProfile {
            aci: [1; 16],
            profile_key,
            expire_timer: 0,
            expire_timer_version: 1,
        };
        assert_eq!(fetch([2; 32]).key(), fetch([3; 32]).key());
        assert_ne!(Job::AnswerContacts.key(), Job::AnswerKeys.key());
    }

    #[test]
    fn a_job_waits_longer_each_time_and_is_given_up() {
        assert!(backoff(1, false).unwrap() < backoff(2, false).unwrap());
        assert!(backoff(6, false).is_some());
        assert!(backoff(7, false).is_none());
    }

    #[test]
    fn a_job_the_connection_failed_is_not_given_up() {
        assert_eq!(backoff(1, true), backoff(1, false));
        assert_eq!(backoff(70, true), backoff(6, false));
    }
}
