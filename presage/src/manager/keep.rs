use libsignal_service::{
    content::{Content, ContentBody},
    prelude::Uuid,
    proto::{
        addressable_message::Author,
        data_message::Delete,
        sync_message::{self, Content as SyncContent},
        DataMessage, EditMessage, NullMessage, SyncMessage,
    },
    protocol::{Aci, ServiceId},
};
use tracing::{debug, warn};

use crate::store::{ContentExt, Store, Thread};
use crate::Error;

/// How long after sending a message its sender can still delete it for everyone, as received.
/// See Signal-Android's [RemoteDeleteUtil](https://github.com/signalapp/Signal-Android/blob/main/app/src/main/java/org/thoughtcrime/securesms/util/RemoteDeleteUtil.kt).
const DELETE_FOR_EVERYONE_WINDOW_MS: u64 = 2 * 24 * 60 * 60 * 1000;

/// What [`keep`] did with a message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kept {
    /// Stored in `thread` under `timestamp`, where [`ContentsStore::message`] finds it.
    ///
    /// [`ContentsStore::message`]: crate::store::ContentsStore::message
    Stored { thread: Thread, timestamp: u64 },
    /// An edit, stored in the place of the message sent at `timestamp`.
    Edited { thread: Thread, timestamp: u64 },
    /// The message sent at `timestamp` deleted for everyone.
    Deleted { thread: Thread, timestamp: u64 },
    /// Nothing stored: there was nothing to store, or it wasn't the sender's to change (see the
    /// log).
    NotStored,
}

/// Stores `message` as receiving does: a delete or an edit applied to the sender's own message,
/// a receipt beside the messages, a contact's expire timer updated. `thread` names the thread of
/// an outgoing message, which its content doesn't say.
pub async fn keep<S: Store>(
    store: &mut S,
    message: &Content,
    thread: Option<Thread>,
) -> Result<Kept, Error<S::Error>> {
    let thread = match thread {
        Some(thread) => thread,
        None => Thread::try_from(message)?,
    };

    let stored = match &message.body {
        ContentBody::DecryptionErrorMessage(e) => {
            warn!(error = ?e, "was asked to save a DecryptionErrorMessage; this should not happen");
            return Ok(Kept::NotStored);
        }
        ContentBody::NullMessage(_) => message.clone(),
        ContentBody::DataMessage(data_message)
        | ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    message: Some(data_message),
                    ..
                })),
            ..
        }) => {
            // The expire timer fields of data messages are only for contacts; a group's timer
            // changes with its revision.
            if let Thread::Contact(_) = thread {
                let version = data_message.expire_timer_version.unwrap_or(1);
                store
                    .update_expire_timer(
                        &thread,
                        data_message.expire_timer.unwrap_or_default(),
                        version,
                    )
                    .await?;
            }

            if let DataMessage {
                delete:
                    Some(Delete {
                        target_sent_timestamp: Some(ts),
                    }),
                ..
            } = data_message
            {
                return delete_for_everyone(store, thread, message, *ts).await;
            }
            message.clone()
        }
        ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(SyncContent::DeleteForMe(delete)),
            ..
        }) => {
            for d in delete.message_deletes.iter().flat_map(|m| &m.messages) {
                let sender = match &d.author {
                    Some(Author::AuthorServiceId(id)) => {
                        ServiceId::parse_from_service_id_string(id)
                    }
                    Some(Author::AuthorServiceIdBinary(id)) => {
                        ServiceId::parse_from_service_id_binary(id)
                    }
                    Some(Author::AuthorE164(_)) | None => None,
                };
                let Some(sender) = sender else {
                    warn!("Could not parse author of delete-for-self message; ignoring.");
                    continue;
                };
                let Some(timestamp) = d.sent_timestamp else {
                    warn!("Timestamp of delete-for-self message not given; ignoring.");
                    continue;
                };
                let Ok(Some(thread)) = store
                    .thread_for_sender_and_timestamp(&sender, timestamp)
                    .await
                else {
                    warn!("Message referenced by delete-for-self message not found; ignoring.");
                    continue;
                };
                // Gone, not marked deleted: Signal-Desktop takes it out of the timeline too.
                let result = store.delete_message(&thread, timestamp).await;
                if !result.is_ok_and(|d| d) {
                    warn!(
                        "Could not delete message referenced by delete-for-self message; ignoring."
                    );
                }
            }
            return Ok(Kept::NotStored);
        }
        ContentBody::EditMessage(EditMessage {
            target_sent_timestamp: Some(target),
            data_message: Some(_),
        })
        | ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    edit_message:
                        Some(EditMessage {
                            target_sent_timestamp: Some(target),
                            data_message: Some(_),
                        }),
                    ..
                })),
            ..
        }) => return edit(store, thread, message, *target).await,
        // Call signaling is transient; calls are recorded by `CallEvent`s instead.
        ContentBody::CallMessage(_) => return Ok(Kept::NotStored),
        ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(SyncContent::CallEvent(_)),
            ..
        }) => message.clone(),
        ContentBody::SynchronizeMessage(msg) => {
            debug!(
                ?msg,
                "skipping saving sync message without interesting fields"
            );
            return Ok(Kept::NotStored);
        }
        ContentBody::ReceiptMessage(_) => message.clone(),
        ContentBody::TypingMessage(msg) => {
            debug!(?msg, "skipping saving typing message");
            return Ok(Kept::NotStored);
        }
        ContentBody::StoryMessage(msg) => {
            debug!(?msg, "skipping story message");
            return Ok(Kept::NotStored);
        }
        ContentBody::EditMessage(msg) => {
            debug!(?msg, "invalid edited");
            return Ok(Kept::NotStored);
        }
    };

    // Messages are stored by thread and time, so a sender's message must not take the place of
    // someone else's, and a receipt at the millisecond of a message must not take its place
    // or keep it out.
    let timestamp = stored.metadata.client_timestamp.timestamp_millis() as u64;
    let receipt = |content: &Content| matches!(content.body, ContentBody::ReceiptMessage(_));
    match store.message(&thread, timestamp).await? {
        Some(existing) if receipt(&stored) && !receipt(&existing) => {
            debug!(%thread, timestamp, "not saving a receipt in the place of a message");
            Ok(Kept::NotStored)
        }
        Some(existing)
            if existing.metadata.sender != stored.metadata.sender && !receipt(&existing) =>
        {
            warn!(%thread, timestamp, "not saving a message in the place of someone else's");
            Ok(Kept::NotStored)
        }
        _ => {
            store.save_message(&thread, stored).await?;
            Ok(Kept::Stored { thread, timestamp })
        }
    }
}

/// Replaces the sender's message sent at `target` by an empty `NullMessage`, if it is recent
/// enough.
async fn delete_for_everyone<S: Store>(
    store: &mut S,
    thread: Thread,
    message: &Content,
    target: u64,
) -> Result<Kept, Error<S::Error>> {
    let sent = message.metadata.client_timestamp.timestamp_millis() as u64;
    match store.message_sent_or_edited_at(&thread, target).await? {
        Some(mut existing)
            if existing.metadata.sender == message.metadata.sender
                && sent.saturating_sub(target) < DELETE_FOR_EVERYONE_WINDOW_MS =>
        {
            let timestamp = existing.metadata.client_timestamp.timestamp_millis() as u64;
            existing.metadata.sender = Aci::from(Uuid::nil()).into();
            existing.body = NullMessage::default().into();
            store.save_message(&thread, existing).await?;
            debug!(%thread, timestamp, "message in thread deleted");
            Ok(Kept::Deleted { thread, timestamp })
        }
        Some(_) => {
            warn!(%thread, target, "ignoring delete of a message by someone else or too old");
            Ok(Kept::NotStored)
        }
        None => {
            warn!(%thread, target, "could not find message to delete in thread");
            Ok(Kept::NotStored)
        }
    }
}

/// Stores an edit in the place of the message it edits, which must be its sender's, naming it
/// by its first time, also when the edit names an earlier edit's.
async fn edit<S: Store>(
    store: &mut S,
    thread: Thread,
    message: &Content,
    target: u64,
) -> Result<Kept, Error<S::Error>> {
    match store.message_sent_or_edited_at(&thread, target).await? {
        Some(original) if original.metadata.sender == message.metadata.sender => {
            let mut edit = message.clone();
            edit.metadata.client_timestamp = original.metadata.client_timestamp;
            retarget_edit(&mut edit, original.timestamp());
            let timestamp = edit.metadata.client_timestamp.timestamp_millis() as u64;
            store.save_message(&thread, edit).await?;
            Ok(Kept::Edited { thread, timestamp })
        }
        _ => {
            warn!(%thread, target, "ignoring edit of a message by someone else or not found");
            Ok(Kept::NotStored)
        }
    }
}

fn retarget_edit(edit: &mut Content, original: u64) {
    match &mut edit.body {
        ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    edit_message: Some(edit),
                    ..
                })),
            ..
        })
        | ContentBody::EditMessage(edit) => edit.target_sent_timestamp = Some(original),
        _ => {}
    }
}
