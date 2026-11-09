//! `presage::manager::keep`, against the SQLite store.

use chrono::{TimeZone, Utc};
use presage::libsignal_service::content::{Content, ContentBody, Metadata};
use presage::libsignal_service::proto::{
    data_message::Delete, DataMessage, EditMessage, ReceiptMessage, TypingMessage,
};
use presage::libsignal_service::protocol::ServiceId;
use presage::libsignal_service::push_service::DEFAULT_DEVICE_ID;
use presage::manager::{keep, Kept};
use presage::store::{ContentsStore, Thread};
use presage_store_sqlite::{OnNewIdentity, SqliteStore};

const ALICE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BOB: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const TWO_DAYS_MS: u64 = 2 * 24 * 60 * 60 * 1000;

fn id(s: &str) -> ServiceId {
    ServiceId::parse_from_service_id_string(s).unwrap()
}

fn content(sender: &str, timestamp: u64, body: ContentBody) -> Content {
    let at = Utc.timestamp_millis_opt(timestamp as i64).unwrap();
    Content {
        metadata: Metadata {
            sender: id(sender),
            destination: id(BOB),
            sender_device: *DEFAULT_DEVICE_ID,
            server_guid: None,
            client_timestamp: at,
            server_timestamp: at,
            needs_receipt: false,
            unidentified_sender: false,
            was_plaintext: false,
            pni_verified: None,
        },
        body,
    }
}

fn text(sender: &str, timestamp: u64, body: &str) -> Content {
    content(
        sender,
        timestamp,
        ContentBody::DataMessage(DataMessage {
            body: Some(body.to_owned()),
            timestamp: Some(timestamp),
            ..Default::default()
        }),
    )
}

fn delete(sender: &str, timestamp: u64, target: u64) -> Content {
    content(
        sender,
        timestamp,
        ContentBody::DataMessage(DataMessage {
            timestamp: Some(timestamp),
            delete: Some(Delete {
                target_sent_timestamp: Some(target),
            }),
            ..Default::default()
        }),
    )
}

fn edit(sender: &str, timestamp: u64, target: u64, body: &str) -> Content {
    content(
        sender,
        timestamp,
        ContentBody::EditMessage(EditMessage {
            target_sent_timestamp: Some(target),
            data_message: Some(DataMessage {
                body: Some(body.to_owned()),
                timestamp: Some(timestamp),
                ..Default::default()
            }),
        }),
    )
}

async fn store() -> SqliteStore {
    SqliteStore::open(":memory:", OnNewIdentity::Trust)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_message_is_stored_in_its_senders_thread() {
    let mut store = store().await;
    let kept = keep(&mut store, &text(ALICE, 1000, "hi"), None)
        .await
        .unwrap();
    assert_eq!(
        kept,
        Kept::Stored {
            thread: Thread::Contact(id(ALICE)),
            timestamp: 1000
        }
    );
}

#[tokio::test]
async fn only_the_sender_deletes_their_message() {
    let mut store = store().await;
    keep(&mut store, &text(ALICE, 1000, "hi"), None)
        .await
        .unwrap();
    let thread = Thread::Contact(id(ALICE));
    // Bob's delete of Alice's message, in Alice's thread by the override.
    let refused = keep(&mut store, &delete(BOB, 2000, 1000), Some(thread.clone()))
        .await
        .unwrap();
    assert_eq!(refused, Kept::NotStored);
    let deleted = keep(&mut store, &delete(ALICE, 2000, 1000), None)
        .await
        .unwrap();
    assert_eq!(
        deleted,
        Kept::Deleted {
            thread: thread.clone(),
            timestamp: 1000
        }
    );
    let stored = store.message(&thread, 1000).await.unwrap().unwrap();
    assert!(matches!(stored.body, ContentBody::NullMessage(_)));
}

#[tokio::test]
async fn a_delete_after_two_days_is_refused() {
    let mut store = store().await;
    keep(&mut store, &text(ALICE, 1000, "hi"), None)
        .await
        .unwrap();
    let refused = keep(&mut store, &delete(ALICE, 1000 + TWO_DAYS_MS, 1000), None)
        .await
        .unwrap();
    assert_eq!(refused, Kept::NotStored);
}

#[tokio::test]
async fn a_second_edit_names_the_first_edits_time() {
    let mut store = store().await;
    let thread = Thread::Contact(id(ALICE));
    keep(&mut store, &text(ALICE, 1000, "one"), None)
        .await
        .unwrap();
    let first = keep(&mut store, &edit(ALICE, 2000, 1000, "two"), None)
        .await
        .unwrap();
    assert_eq!(
        first,
        Kept::Edited {
            thread: thread.clone(),
            timestamp: 1000
        }
    );
    // Signal's apps name the message by its latest edit.
    let second = keep(&mut store, &edit(ALICE, 3000, 2000, "three"), None)
        .await
        .unwrap();
    assert_eq!(
        second,
        Kept::Edited {
            thread: thread.clone(),
            timestamp: 1000
        }
    );
    let stored = store.message(&thread, 1000).await.unwrap().unwrap();
    let ContentBody::EditMessage(edit) = stored.body else {
        panic!("the edit takes the message's place");
    };
    assert_eq!(edit.target_sent_timestamp, Some(1000));
    assert_eq!(edit.data_message.unwrap().body.as_deref(), Some("three"));
}

#[tokio::test]
async fn an_edit_by_someone_else_is_refused() {
    let mut store = store().await;
    keep(&mut store, &text(ALICE, 1000, "one"), None)
        .await
        .unwrap();
    let thread = Thread::Contact(id(ALICE));
    let refused = keep(&mut store, &edit(BOB, 2000, 1000, "two"), Some(thread))
        .await
        .unwrap();
    assert_eq!(refused, Kept::NotStored);
}

#[tokio::test]
async fn a_receipt_gives_way_to_a_message_at_the_same_millisecond() {
    let mut store = store().await;
    let thread = Thread::Contact(id(ALICE));
    let receipt = content(
        ALICE,
        1000,
        ContentBody::ReceiptMessage(ReceiptMessage {
            r#type: Some(1),
            timestamp: vec![500],
        }),
    );
    // The receipt first: the message takes its place.
    keep(&mut store, &receipt, None).await.unwrap();
    let message = keep(&mut store, &text(ALICE, 1000, "hi"), None)
        .await
        .unwrap();
    assert_eq!(
        message,
        Kept::Stored {
            thread: thread.clone(),
            timestamp: 1000
        }
    );
    // The message first: the receipt gives way.
    let again = keep(&mut store, &receipt, None).await.unwrap();
    assert_eq!(again, Kept::NotStored);
    let stored = store.message(&thread, 1000).await.unwrap().unwrap();
    assert!(matches!(stored.body, ContentBody::DataMessage(_)));
}

#[tokio::test]
async fn typing_is_not_stored() {
    let mut store = store().await;
    let typing = content(
        ALICE,
        1000,
        ContentBody::TypingMessage(TypingMessage::default()),
    );
    let kept = keep(&mut store, &typing, None).await.unwrap();
    assert_eq!(kept, Kept::NotStored);
}

#[tokio::test]
async fn a_message_does_not_take_the_place_of_someone_elses() {
    let mut store = store().await;
    let thread = Thread::Contact(id(ALICE));
    keep(&mut store, &text(ALICE, 1000, "mine"), None)
        .await
        .unwrap();
    let theirs = keep(&mut store, &text(BOB, 1000, "theirs"), Some(thread.clone()))
        .await
        .unwrap();
    assert_eq!(theirs, Kept::NotStored);
    let stored = store.message(&thread, 1000).await.unwrap().unwrap();
    assert_eq!(stored.metadata.sender, id(ALICE));
}
