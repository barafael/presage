use libsignal_service::{
    content::{Content, ContentBody},
    proto::{
        addressable_message::Author,
        data_message::Delete,
        sync_message::{self, Content as SyncContent},
        DataMessage, EditMessage, SyncMessage,
    },
    protocol::ServiceId,
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
    /// Stored in `thread` under its sender and `timestamp`, where [`ContentsStore::message`]
    /// finds it.
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
                let result = store.delete_message(&thread, &sender, timestamp).await;
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

    // Messages are stored by thread, sender and time: two senders' at one millisecond are both
    // kept, and one only takes the place of its sender's own (see `replaces`).
    let timestamp = stored.metadata.client_timestamp.timestamp_millis() as u64;
    match store
        .message(&thread, &stored.metadata.sender, timestamp)
        .await?
    {
        Some(existing) if !replaces(&existing, &stored) => {
            debug!(%thread, timestamp, "not saving a message in the place of its sender's other one");
            Ok(Kept::NotStored)
        }
        _ => {
            store.save_message(&thread, stored).await?;
            Ok(Kept::Stored { thread, timestamp })
        }
    }
}

/// Whether `message` takes the place of `existing`, its sender's at the same time in a thread.
/// A receipt doesn't take a message's place, nor keep it out. Of two messages one account's
/// devices sent at one millisecond, the first stays: they have one name, and the first is the
/// one already handed on. An edit takes its message's place from any of them.
fn replaces(existing: &Content, message: &Content) -> bool {
    let receipt = |content: &Content| matches!(content.body, ContentBody::ReceiptMessage(_));
    receipt(existing)
        || !receipt(message)
            && (existing.metadata.sender_device == message.metadata.sender_device
                || message.edited_at().is_some())
}

/// Deletes the sender's message sent at `target` (or last edited then), if it is recent enough:
/// gone from the store, as Signal-Desktop takes it out of the timeline.
async fn delete_for_everyone<S: Store>(
    store: &mut S,
    thread: Thread,
    message: &Content,
    target: u64,
) -> Result<Kept, Error<S::Error>> {
    let sent = message.metadata.client_timestamp.timestamp_millis() as u64;
    let sender = message.metadata.sender;
    match store
        .message_sent_or_edited_at(&thread, &sender, target)
        .await?
    {
        Some(existing) if sent.saturating_sub(target) < DELETE_FOR_EVERYONE_WINDOW_MS => {
            let timestamp = existing.metadata.client_timestamp.timestamp_millis() as u64;
            store.delete_message(&thread, &sender, timestamp).await?;
            debug!(%thread, timestamp, "message in thread deleted");
            Ok(Kept::Deleted { thread, timestamp })
        }
        Some(_) => {
            warn!(%thread, target, "ignoring delete of a message too old");
            Ok(Kept::NotStored)
        }
        None => {
            warn!(%thread, target, "could not find the sender's message to delete in thread");
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
    match store
        .message_sent_or_edited_at(&thread, &message.metadata.sender, target)
        .await?
    {
        Some(original) => {
            let mut edit = message.clone();
            edit.metadata.client_timestamp = original.metadata.client_timestamp;
            retarget_edit(&mut edit, original.timestamp());
            let timestamp = edit.metadata.client_timestamp.timestamp_millis() as u64;
            store.save_message(&thread, edit).await?;
            Ok(Kept::Edited { thread, timestamp })
        }
        None => {
            warn!(%thread, target, "ignoring an edit of a message the sender has none of there");
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

#[cfg(test)]
mod tests {
    use libsignal_service::{
        content::{Content, ContentBody, Metadata},
        prelude::Uuid,
        proto::{receipt_message, DataMessage, EditMessage, ReceiptMessage},
        protocol::{Aci, ServiceId},
    };

    use super::replaces;

    fn from_device(device: u8, body: ContentBody) -> Content {
        let sender = ServiceId::Aci(Aci::from(Uuid::from_u128(1)));
        let at = chrono::DateTime::from_timestamp_millis(1_000).unwrap();
        Content {
            metadata: Metadata {
                sender,
                destination: sender,
                sender_device: device.try_into().unwrap(),
                client_timestamp: at,
                server_timestamp: at,
                needs_receipt: false,
                unidentified_sender: false,
                server_guid: None,
                was_plaintext: false,
                pni_verified: None,
            },
            body,
        }
    }

    fn data(device: u8) -> Content {
        from_device(
            device,
            ContentBody::DataMessage(DataMessage {
                timestamp: Some(1_000),
                ..Default::default()
            }),
        )
    }

    fn receipt(device: u8) -> Content {
        from_device(
            device,
            ContentBody::ReceiptMessage(ReceiptMessage {
                r#type: Some(receipt_message::Type::Read.into()),
                timestamp: vec![500],
            }),
        )
    }

    fn edit(device: u8) -> Content {
        from_device(
            device,
            ContentBody::EditMessage(EditMessage {
                target_sent_timestamp: Some(1_000),
                data_message: Some(DataMessage {
                    timestamp: Some(2_000),
                    ..Default::default()
                }),
            }),
        )
    }

    #[test]
    fn the_first_of_one_accounts_messages_at_a_millisecond_stays() {
        assert!(replaces(&data(1), &data(1)), "the same device's again");
        assert!(!replaces(&data(1), &data(2)), "another device's");
        assert!(replaces(&data(1), &edit(2)), "an edit, from any device");
        assert!(replaces(&edit(1), &edit(2)), "a later edit");
    }

    #[test]
    fn a_receipt_gives_way() {
        assert!(!replaces(&data(1), &receipt(1)));
        assert!(replaces(&receipt(1), &data(1)));
        assert!(replaces(&receipt(1), &data(2)));
        assert!(replaces(&receipt(1), &receipt(1)));
    }
}
