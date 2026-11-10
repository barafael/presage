use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::channel::{mpsc, oneshot};
use futures::future::{self, Either};
use futures::{pin_mut, Stream, StreamExt};
use libsignal_service::cipher::SealedSenderDecryptionError;
use libsignal_service::content::sync_message::request::Type as RequestType;
use libsignal_service::envelope::Envelope;
use libsignal_service::messagepipe::AckHandle;
use libsignal_service::prelude::{Content, ProtobufMessage, ServiceError};
use libsignal_service::protocol::{DeviceId, ProtocolAddress, PublicKey};
use libsignal_service::session_lock::SessionLock;
use libsignal_service::{
    content::ContentBody,
    encrypt_device_name,
    groups_v2::GroupsManager,
    messagepipe::{Incoming, MessagePipe},
    proto::{
        sync_message::{self, sticker_pack_operation, Content as SyncContent},
        DataMessage, GroupContextV2, SyncMessage,
    },
    protocol::{IdentityKeyStore, ServiceId, ServiceIdKind},
    push_service::{PushService, ServiceIds},
    websocket::account::{AccountAttributes, DeviceCapabilities},
    AccountManager,
};
use rand::rng;
use tracing::{debug, error, info, trace, warn};

use super::groups::update_group;
use super::{jobs, save_message, Registered, RegistrationData, RegistrationType, ServiceCipher};
use crate::manager::group_credentials::GroupCredentialsCache;
use crate::manager::Kept;
use crate::model::jobs::Job;
use crate::model::messages::Received;
use crate::store::Store;
use crate::{Error, Manager};

impl<S: Store> Manager<S, Registered> {
    /// Starts receiving and storing messages.
    ///
    /// As a client, it is heavily recommended to process incoming messages and wait for the `Received::QueueEmpty` messages
    /// until giving the ability for users to send messages. That way, all possible updates (sessions, profile keys, sender keys)
    /// are processed _before_ trying to encrypt and send messages, which might get rejected by recipients otherwise.
    ///
    /// Returns the [`Messages`] to consume. Messages will also be stored by the implementation of the [Store].
    ///
    /// Receiving runs on a thread of its own, on the runtime this is called on, until the
    /// [`Messages`] are dropped: that thread decrypts and stores, and runs the
    /// [jobs](crate::model::jobs::Job) the store keeps. It reads the next envelope when the
    /// stream is asked for the next message, not before.
    pub async fn receive_messages(&mut self) -> Result<Messages, Error<S::Error>> {
        let (events, received) = tokio::sync::mpsc::channel(1);
        let (ready, started) = oneshot::channel();
        let wanted = Arc::new(tokio::sync::Notify::new());
        let manager = self.clone();
        let runtime = tokio::runtime::Handle::current();
        let asked = wanted.clone();
        std::thread::Builder::new()
            .name("presage-receive".into())
            .spawn(move || {
                // The protocol stores' futures aren't `Send`: they stay on this thread.
                let local = tokio::task::LocalSet::new();
                runtime.block_on(local.run_until(drive(manager, ready, events, asked)));
            })?;
        started
            .await
            .map_err(|_| Error::MessagePipeInterruptedError)??;
        Ok(Messages {
            received,
            wanted,
            asked: false,
        })
    }
}

/// What [`Manager::receive_messages`] receives, until dropped.
#[derive(Debug)]
pub struct Messages {
    received: tokio::sync::mpsc::Receiver<Received>,
    /// Tells the receiving thread that the next message is waited for.
    wanted: Arc<tokio::sync::Notify>,
    asked: bool,
}

impl Stream for Messages {
    type Item = Received;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Received>> {
        let next = self.received.poll_recv(cx);
        match next {
            Poll::Ready(_) => self.asked = false,
            Poll::Pending if !self.asked => {
                self.asked = true;
                self.wanted.notify_one();
            }
            Poll::Pending => {}
        }
        next
    }
}

/// Receives until the [`Messages`] are dropped or the connection ends, with the jobs running
/// beside.
async fn drive<S: Store>(
    mut manager: Manager<S, Registered>,
    ready: oneshot::Sender<Result<(), Error<S::Error>>>,
    events: tokio::sync::mpsc::Sender<Received>,
    wanted: Arc<tokio::sync::Notify>,
) {
    let (told, background) = mpsc::unbounded();
    let (mut receiver, mut account_manager) = match Receiver::new(&mut manager, background).await {
        Ok(started) => {
            let _ = ready.send(Ok(()));
            started
        }
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    debug!("starting to consume incoming message stream");

    let store = manager.store.clone();
    let registration_data = manager.registration_data().clone();
    tokio::task::spawn_local(async move {
        if let Err(error) =
            set_account_attributes(&mut account_manager, &store, &registration_data).await
        {
            error!(%error, "failed to set account attributes, this is problematic and should never happen!");
        }
        if let Err(error) = register_pre_keys(&store, &mut account_manager).await {
            error!(%error, "failed to register pre-keys, this is problematic and should never happen!");
        }
    });
    tokio::task::spawn_local(jobs::run(manager, told));

    loop {
        // As a stream polled would: nothing is read before the next message is asked for, so
        // that the client sees the store as its last message left it.
        let received = {
            let next = async {
                wanted.notified().await;
                receiver.next().await
            };
            let dropped = events.closed();
            pin_mut!(next, dropped);
            match future::select(next, dropped).await {
                Either::Left((received, _)) => received,
                // Stopped mid-envelope: it comes again.
                Either::Right(_) => return,
            }
        };
        let Some(received) = received else {
            return;
        };
        if events.send(received).await.is_err() {
            return;
        }
    }
}

struct Receiver<S: Store, E> {
    store: S,
    envelopes: E,
    session_lock: SessionLock,
    trust_roots: Vec<PublicKey>,
    aci_address: ProtocolAddress,
    pni_address: ProtocolAddress,
    groups_manager: GroupsManager<GroupCredentialsCache>,
    identified_push_service: PushService,
    service_ids: ServiceIds,
    registration_type: RegistrationType,
    jobs_wake: Arc<tokio::sync::Notify>,
    /// Decrypted and kept before the receiver stopped, but not handled: handled first.
    decrypted: VecDeque<(u64, Content)>,
    /// Told before the next envelope is read.
    pending: VecDeque<Received>,
    /// What the jobs bring.
    background: mpsc::UnboundedReceiver<Received>,
}

type Envelopes = Pin<Box<dyn Stream<Item = Result<Incoming, ServiceError>>>>;

impl<S: Store> Receiver<S, Envelopes> {
    async fn new(
        manager: &mut Manager<S, Registered>,
        background: mpsc::UnboundedReceiver<Received>,
    ) -> Result<(Self, AccountManager), Error<S::Error>> {
        let identified_push_service = manager.identified_push_service();
        // NB: here, we initialise a *fresh* Signal websocket, which means any other use of the previous one will go into nirvana
        let identified_websocket = manager.identified_websocket(true).await?;
        let account_manager = AccountManager::new(
            identified_push_service.clone(),
            identified_websocket.clone(),
            None,
        );
        let service_configuration = manager.state.service_configuration();
        // A primary makes its pool when first asked.
        manager.account_entropy_pool().await?;

        let receiver = Self {
            store: manager.store.clone(),
            envelopes: Box::pin(MessagePipe::from_socket(identified_websocket).stream()),
            session_lock: manager.state.session_lock.clone(),
            trust_roots: service_configuration.unidentified_sender_trust_roots,
            aci_address: ProtocolAddress::new(
                manager.state.data.service_ids.aci().service_id_string(),
                manager.state.device_id(),
            ),
            pni_address: ProtocolAddress::new(
                manager.state.data.service_ids.pni().service_id_string(),
                manager.state.device_id(),
            ),
            groups_manager: Box::pin(manager.groups_manager()).await?,
            identified_push_service,
            service_ids: manager.state.data.service_ids.clone(),
            registration_type: manager.registration_type(),
            jobs_wake: manager.state.jobs_wake.clone(),
            decrypted: manager
                .store
                .decrypted()
                .await
                .unwrap_or_else(|error| {
                    error!(%error, "failed to load the messages decrypted and not handled");
                    Vec::new()
                })
                .into(),
            pending: VecDeque::new(),
            background,
        };
        Ok((receiver, account_manager))
    }
}

/// What an envelope held.
enum Opened {
    /// Decrypted, and kept as `id` until handled.
    Content {
        id: u64,
        content: Box<Content>,
    },
    Failed(Received),
    Nothing,
}

impl<S, E> Receiver<S, E>
where
    S: Store,
    E: Stream<Item = Result<Incoming, ServiceError>> + Unpin,
{
    async fn next(&mut self) -> Option<Received> {
        loop {
            if let Some(received) = self.pending.pop_front() {
                return Some(received);
            }
            if let Some((id, content)) = self.decrypted.pop_front() {
                debug!(
                    id,
                    "handling a message decrypted before the receiver stopped"
                );
                let received = self.handle(content).await;
                self.handled(id).await;
                self.pending.extend(received);
                continue;
            }
            let incoming = match future::select(self.background.next(), self.envelopes.next()).await
            {
                Either::Left((Some(received), _)) => return Some(received),
                Either::Left((None, incoming)) => incoming.await,
                Either::Right((incoming, _)) => incoming,
            };
            match incoming {
                Some(Ok(Incoming::Envelope { envelope, ack })) => {
                    match self.open(envelope, ack).await {
                        Opened::Content { id, content } => {
                            let received = self.handle(*content).await;
                            self.handled(id).await;
                            self.pending.extend(received);
                        }
                        Opened::Failed(received) => self.pending.push_back(received),
                        Opened::Nothing => {}
                    }
                }
                Some(Ok(Incoming::QueueEmpty)) => {
                    debug!("got empty queue");
                    match self.store.fetch_account_entropy_pool().await {
                        Ok(None) => {
                            debug!("device does not have the needed keys; requesting from primary device");
                            self.enqueue(Job::RequestKeys).await;
                        }
                        Ok(Some(_)) => {}
                        Err(error) => error!(%error, "failed to read the account entropy pool"),
                    }
                    return Some(Received::QueueEmpty);
                }
                Some(Err(error)) => {
                    error!(%error, "unexpected error in message receiving loop")
                }
                None => return None,
            }
        }
    }

    /// Decrypts `envelope` in one session step and one store transaction, which also keeps what
    /// it held, and acknowledges it once committed. A receiver stopping before that leaves the
    /// envelope unacknowledged and the session as it was, to decrypt it again when it comes again.
    async fn open(&mut self, envelope: Envelope, ack: AckHandle) -> Opened {
        let source = envelope.parse_source_service_id();
        let source_device = envelope.source_device_id();
        let timestamp = envelope.client_timestamp();
        let destination = envelope.parse_destination_service_id();
        match destination {
            None => {
                warn!("Message has no destination service ID, dropping.");
                ack.ack();
                return Opened::Nothing;
            }
            Some(ServiceId::Pni(pni)) if pni == self.service_ids.pni() && source.is_none() => {
                warn!("Got a sealed sender message to our PNI? Invalid message, ignoring.");
                ack.ack();
                return Opened::Nothing;
            }
            Some(_) => {}
        }

        let session_lock = self.session_lock.clone();
        let step = session_lock.step().await;
        let mut transaction = match self.store.transaction().await {
            Ok(transaction) => transaction,
            Err(error) => {
                error!(%error, "failed to begin a transaction; the envelope comes again");
                return Opened::Nothing;
            }
        };
        // These ciphers take no lock of their own: this step holds the shared one.
        let opened = match destination {
            Some(ServiceId::Pni(_)) => {
                ServiceCipher::new(
                    transaction.pni_protocol_store(),
                    self.trust_roots.clone(),
                    self.pni_address.clone(),
                )
                .open_envelope(envelope, &mut rng())
                .await
            }
            _ => {
                ServiceCipher::new(
                    transaction.aci_protocol_store(),
                    self.trust_roots.clone(),
                    self.aci_address.clone(),
                )
                .open_envelope(envelope, &mut rng())
                .await
            }
        };
        let opened = match opened {
            Ok(Some(content)) => match transaction.keep_decrypted(&content).await {
                Ok(id) => Ok(Some((id, content))),
                Err(error) => {
                    error!(%error, "failed to keep a decrypted message; the envelope comes again");
                    return Opened::Nothing;
                }
            },
            Ok(None) => Ok(None),
            Err(error) => Err(error),
        };
        if let Err(error) = transaction.commit().await {
            error!(%error, "failed to commit a decrypted message; the envelope comes again");
            return Opened::Nothing;
        }
        drop(step);
        ack.ack();

        match opened {
            Ok(Some((id, content))) => Opened::Content {
                id,
                content: Box::new(content),
            },
            Ok(None) => {
                debug!("empty envelope, message will be skipped!");
                Opened::Nothing
            }
            Err(error) => {
                error!(%error, "error opening envelope, message will be skipped!");
                decryption_error(error, source, source_device, timestamp)
                    .map_or(Opened::Nothing, Opened::Failed)
            }
        }
    }

    /// Forgets the decrypted content `id`, now handled.
    async fn handled(&mut self, id: u64) {
        if let Err(error) = self.store.handled(id).await {
            error!(%error, "failed to forget a handled message; it is handled again at the next start");
        }
    }

    /// Handles a decrypted content: stores it, and what else it asks for, as far as its
    /// [`Origin`] may ask it.
    async fn handle(&mut self, content: Content) -> Option<Received> {
        let origin = Origin::of(&content, &self.service_ids);

        if let ContentBody::DecryptionErrorMessage(message) = content.body {
            warn!(
                sender = %content.metadata.sender.service_id_string(),
                device = %content.metadata.sender_device,
                timestamp = message.timestamp,
                "a device of theirs failed to decrypt a message of ours"
            );
            return Some(Received::RetryReceipt {
                sender: content.metadata.sender,
                sender_device: content.metadata.sender_device,
                message,
            });
        }

        match (&origin, &content.body) {
            (Origin::Unauthenticated, _) => {
                warn!(
                    sender = %content.metadata.sender.service_id_string(),
                    "dropping plaintext content that is no retry receipt"
                );
                return None;
            }
            (Origin::Peer, ContentBody::SynchronizeMessage(_)) => {
                warn!(
                    sender = %content.metadata.sender.service_id_string(),
                    "dropping a sync message from another account"
                );
                return None;
            }
            (Origin::Own, ContentBody::SynchronizeMessage(sync)) => {
                if self.handle_sync(OwnSync(sync)).await {
                    return None;
                }
            }
            (Origin::Own | Origin::Peer, _) => {}
        }

        self.handle_message(content).await
    }

    /// What only our own devices may ask: answers, the account's contacts, keys and sticker
    /// packs. Whether the message is nothing more than that.
    async fn handle_sync(&mut self, OwnSync(sync): OwnSync<'_>) -> bool {
        match &sync.content {
            Some(SyncContent::Request(request)) => match request.r#type() {
                RequestType::Contacts => self.enqueue(Job::AnswerContacts).await,
                RequestType::Keys => self.enqueue(Job::AnswerKeys).await,
                // No block list is stored, and an empty answer would clear the requester's.
                RequestType::Blocked => {
                    warn!("not answering a request for the block list: none is stored");
                }
                t => info!(type = ?t, "Got sync request of currently unhandled type"),
            },
            // contacts synchronization sent from the primary device (happens after linking, or on demand)
            Some(SyncContent::Contacts(contacts)) => {
                info!("saving contacts");
                let saved = jobs::save_contacts(
                    &mut self.store,
                    self.identified_push_service.clone(),
                    contacts,
                )
                .await;
                return match saved {
                    Ok(()) => {
                        self.pending.push_back(Received::Contacts);
                        true
                    }
                    Err(error) => {
                        warn!(%error, "failed to save contacts; trying again later");
                        self.enqueue(Job::SaveContacts {
                            contacts: contacts.encode_to_vec(),
                        })
                        .await;
                        true
                    }
                };
            }
            // key synchronization sent from the primary device
            Some(SyncContent::Keys(keys)) => {
                debug!("received key sync message");
                if self.registration_type == RegistrationType::Primary {
                    warn!("received a key sync message as a primary device; ignoring")
                } else if let Some(pool) = jobs::pool_of(keys) {
                    if let Err(error) = self.store.store_account_entropy_pool(Some(&pool)).await {
                        error!(%error, "failed to store account entropy pool");
                    }
                }
            }
            // The primary device told us to fetch stuff again from the storage service.
            Some(SyncContent::FetchLatest(fetch_latest))
                if fetch_latest.r#type() == sync_message::fetch_latest::Type::StorageManifest =>
            {
                self.enqueue(Job::SyncStorage).await;
            }
            _ => {}
        }

        for operation in &sync.sticker_pack_operation {
            match operation.r#type() {
                sticker_pack_operation::Type::Install => {
                    self.enqueue(Job::InstallStickerPack {
                        pack_id: operation.pack_id().to_vec(),
                        pack_key: operation.pack_key().to_vec(),
                    })
                    .await;
                }
                sticker_pack_operation::Type::Remove => {
                    match self.store.remove_sticker_pack(operation.pack_id()).await {
                        Ok(was_present) => debug!(was_present, "removed stick pack"),
                        Err(error) => error!(%error, "failed to remove sticker pack"),
                    }
                }
            }
        }
        false
    }

    async fn enqueue(&mut self, job: Job) {
        jobs::enqueue(&mut self.store, &self.jobs_wake, job).await;
    }

    /// Keeps a message from a peer or from one of our devices, its group brought up to date first.
    async fn handle_message(&mut self, content: Content) -> Option<Received> {
        // group update
        if let ContentBody::DataMessage(DataMessage {
            group_v2:
                Some(GroupContextV2 {
                    master_key: Some(master_key_bytes),
                    revision: Some(revision),
                    group_change,
                }),
            ..
        })
        | ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    message:
                        Some(DataMessage {
                            group_v2:
                                Some(GroupContextV2 {
                                    master_key: Some(master_key_bytes),
                                    revision: Some(revision),
                                    group_change,
                                }),
                            ..
                        }),
                    ..
                })),
            ..
        }) = &content.body
        {
            match update_group(
                &self.store,
                &mut self.groups_manager,
                master_key_bytes,
                *revision,
                group_change.as_deref(),
            )
            .await
            {
                Ok(read) => {
                    // The message tells of its own change.
                    let missed: Vec<_> = read
                        .into_iter()
                        .filter(|changes| {
                            group_change.is_none() || changes.changes.version != *revision
                        })
                        .collect();
                    if let (false, Ok(master_key)) = (
                        missed.is_empty(),
                        <[u8; 32]>::try_from(master_key_bytes.as_slice()),
                    ) {
                        self.pending.push_back(Received::MissedGroupChanges {
                            master_key,
                            changes: missed,
                        });
                    }
                }
                Err(error) => {
                    warn!(%error, "failed to update the group; trying again later");
                    if let Ok(master_key) = <[u8; 32]>::try_from(master_key_bytes.as_slice()) {
                        self.enqueue(Job::UpdateGroup {
                            master_key,
                            revision: *revision,
                        })
                        .await;
                    }
                }
            }
        }

        let kept = save_message(&mut self.store, &self.jobs_wake, &content, None)
            .await
            .unwrap_or_else(|error| {
                error!(%error, "error saving message to store");
                Kept::NotStored
            });

        Some(Received::Content {
            content: Box::new(content),
            kept,
        })
    }
}

/// Who a decrypted content is from, decided once: what it may ask of this device follows from
/// it, and nowhere else.
enum Origin {
    /// One of this account's devices, by a session with it.
    Own,
    /// Another account, by a session with it.
    Peer,
    /// A plaintext envelope: nothing shows who wrote it. Signal's apps take a retry receipt
    /// from one and nothing else.
    Unauthenticated,
}

impl Origin {
    fn of(content: &Content, own: &ServiceIds) -> Self {
        if content.metadata.was_plaintext {
            Self::Unauthenticated
        } else if content.metadata.sender == ServiceId::from(own.aci()) {
            Self::Own
        } else {
            Self::Peer
        }
    }
}

/// A sync message of [`Origin::Own`]: only that changes the account's state on this device.
struct OwnSync<'a>(&'a SyncMessage);

/// Who failed to decrypt with which error, if that is known: a sealed sender once their
/// certificate checked out, an unsealed one from the envelope.
fn decryption_error(
    error: ServiceError,
    source: Option<ServiceId>,
    source_device: u32,
    timestamp: u64,
) -> Option<Received> {
    let (sender, sender_device, error) = match error {
        ServiceError::SealedSenderDecryptionError(SealedSenderDecryptionError {
            sender: Some(sender),
            inner,
        }) => (
            ServiceId::parse_from_service_id_string(sender.name())?,
            sender.device_id(),
            inner,
        ),
        ServiceError::SignalProtocolError(error) => {
            (source?, DeviceId::try_from(source_device).ok()?, error)
        }
        _ => return None,
    };
    Some(Received::DecryptionError {
        sender,
        sender_device,
        timestamp,
        error,
    })
}

async fn set_account_attributes<S: Store>(
    account_manager: &mut AccountManager,
    store: &S,
    data: &RegistrationData,
) -> Result<(), Error<S::Error>> {
    trace!("setting account attributes");

    let pni_registration_id = data.pni_registration_id.ok_or(Error::RelinkNecessary)?;

    let name = if let Some(device_name) = data.device_name() {
        let aci_key_pair = store.aci_protocol_store().get_identity_key_pair().await?;
        let mut rng = rng();
        Some(encrypt_device_name(
            &mut rng,
            device_name,
            aci_key_pair.identity_key(),
        )?)
    } else {
        None
    };

    account_manager
        .set_account_attributes(AccountAttributes {
            fetches_messages: true,
            registration_id: data.registration_id,
            pni_registration_id,
            name,
            registration_lock: None,
            unidentified_access_key: Some(data.profile_key.derive_access_key().to_vec()),
            unrestricted_unidentified_access: false,
            capabilities: Some(DeviceCapabilities {
                storage: true,
                transfer: false,
                attachment_backfill: false,
                spqr: true,
                profiles_v2: false,
                username_change_sync_message: true,
            }),
            discoverable_by_phone_number: true,
            recovery_password: None,
            video: false,
            voice: false,
        })
        .await?;

    trace!("done setting account attributes");
    Ok(())
}

async fn register_pre_keys<S: Store>(
    store: &S,
    account_manager: &mut AccountManager,
) -> Result<(), Error<S::Error>> {
    trace!("registering pre keys");

    account_manager
        .update_pre_key_bundle(&mut store.aci_protocol_store(), ServiceIdKind::Aci, true)
        .await?;

    account_manager
        .update_pre_key_bundle(&mut store.pni_protocol_store(), ServiceIdKind::Pni, true)
        .await?;

    trace!("registered pre keys");
    Ok(())
}

#[cfg(test)]
mod tests {
    use libsignal_service::content::{Content, ContentBody, Metadata};
    use libsignal_service::prelude::Uuid;
    use libsignal_service::proto::NullMessage;
    use libsignal_service::protocol::{Aci, ServiceId};
    use libsignal_service::push_service::ServiceIds;

    use super::{Messages, Origin, Received};
    use futures::StreamExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// The receiving thread's side of [`Messages`]: produces one message per asking.
    #[tokio::test]
    async fn nothing_is_read_before_the_next_message_is_asked_for() {
        let (events, received) = tokio::sync::mpsc::channel(1);
        let wanted = Arc::new(tokio::sync::Notify::new());
        let read = Arc::new(AtomicUsize::new(0));
        let mut messages = Messages {
            received,
            wanted: wanted.clone(),
            asked: false,
        };
        let reading = read.clone();
        tokio::spawn(async move {
            loop {
                wanted.notified().await;
                reading.fetch_add(1, Ordering::SeqCst);
                if events.send(Received::QueueEmpty).await.is_err() {
                    return;
                }
            }
        });

        tokio::task::yield_now().await;
        assert_eq!(read.load(Ordering::SeqCst), 0, "not asked yet");
        for asked in 1..=3 {
            assert!(matches!(messages.next().await, Some(Received::QueueEmpty)));
            tokio::task::yield_now().await;
            assert_eq!(read.load(Ordering::SeqCst), asked, "one read per asking");
        }
    }

    fn content(sender: Uuid, was_plaintext: bool) -> Content {
        let sender: ServiceId = Aci::from(sender).into();
        let now = chrono::Utc::now();
        Content {
            metadata: Metadata {
                sender,
                sender_device: 1.try_into().unwrap(),
                destination: sender,
                server_guid: None,
                client_timestamp: now,
                server_timestamp: now,
                needs_receipt: false,
                unidentified_sender: false,
                was_plaintext,
                pni_verified: None,
            },
            body: ContentBody::NullMessage(NullMessage::default()),
        }
    }

    #[test]
    fn origin_is_decided_by_session_and_sender() {
        let own = ServiceIds {
            aci: Uuid::from_u128(1),
            pni: Uuid::from_u128(2),
        };
        assert!(matches!(
            Origin::of(&content(own.aci, false), &own),
            Origin::Own
        ));
        assert!(matches!(
            Origin::of(&content(Uuid::from_u128(3), false), &own),
            Origin::Peer
        ));
        // Not ours either, whoever the envelope names.
        assert!(matches!(
            Origin::of(&content(own.aci, true), &own),
            Origin::Unauthenticated
        ));
    }
}
