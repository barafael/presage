use std::str::FromStr;

use std::collections::VecDeque;

use futures::channel::mpsc;
use futures::future::{self, Either};
use futures::{Stream, StreamExt};
use libsignal_service::cipher::SealedSenderDecryptionError;
use libsignal_service::content::sync_message::request::Type as RequestType;
use libsignal_service::envelope::Envelope;
use libsignal_service::libsignal_account_keys::AccountEntropyPool;
use libsignal_service::messagepipe::AckHandle;
use libsignal_service::prelude::{Content, ServiceError};
use libsignal_service::proto::contact_details;
use libsignal_service::protocol::{DeviceId, ProtocolAddress, PublicKey};
use libsignal_service::sender::ContactDetails;
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
    receiver::MessageReceiver,
    websocket::{
        self,
        account::{AccountAttributes, DeviceCapabilities},
        SignalWebSocket,
    },
    AccountManager,
};
use rand::rng;
use tracing::{debug, error, info, trace, warn};

use super::groups::update_group;
use super::{
    download_sticker_pack, save_message, sync_groups_from_storage_service, MessageSender,
    Registered, RegistrationData, RegistrationType, ServiceCipher,
};
use crate::manager::group_credentials::GroupCredentialsCache;
use crate::manager::Kept;
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
    /// Returns a [futures::Stream] of messages to consume. Messages will also be stored by the implementation of the [Store].
    pub async fn receive_messages(
        &mut self,
    ) -> Result<impl Stream<Item = Received>, Error<S::Error>> {
        let identified_push_service = self.identified_push_service();
        // NB: here, we initialise a *fresh* Signal websocket, which means any other use of the previous one will go into nirvana
        let identified_websocket = self.identified_websocket(true).await?;

        let mut account_manager = AccountManager::new(
            identified_push_service.clone(),
            identified_websocket.clone(),
            None,
        );

        let store_inner = self.store.clone();
        let registration_data_inner = self.registration_data().clone();

        // We make a task to update the account attributes and refresh pre keys as needed that will
        // only yield a value if one of the two operations fail (stop signal).
        //
        // This is necessary because in this context, we can't do the classic tokio::spawn with a
        // oneshot::channel() or CancellationToken because of !Send constraints in the Store.
        let refresh_registration_task = async move {
            if let Err(error) =
                set_account_attributes(&mut account_manager, &store_inner, &registration_data_inner)
                    .await
            {
                error!(%error, "failed to set account attributes, this is problematic and should never happen!");
            }

            if let Err(error) = register_pre_keys(&store_inner, &mut account_manager).await {
                error!(%error, "failed to register pre-keys, this is problematic and should never happen!");
            }

            // Never return, which keeps the messages stream alive.
            future::pending::<()>().await
        };

        let encrypted_messages = MessagePipe::from_socket(identified_websocket.clone());
        let (stored_packs_sender, stored_packs) = mpsc::unbounded();
        let service_configuration = self.state.service_configuration();

        let receiver = Receiver {
            store: self.store.clone(),
            identified_websocket,
            unidentified_websocket: self.unidentified_websocket().await?,
            envelopes: Box::pin(encrypted_messages.stream()),
            message_receiver: MessageReceiver::new(identified_push_service.clone()),
            session_lock: self.state.session_lock.clone(),
            trust_roots: service_configuration.unidentified_sender_trust_roots,
            aci_address: ProtocolAddress::new(
                self.state.data.service_ids.aci().service_id_string(),
                self.state.device_id(),
            ),
            pni_address: ProtocolAddress::new(
                self.state.data.service_ids.pni().service_id_string(),
                self.state.device_id(),
            ),
            groups_manager: Box::pin(self.groups_manager()).await?,
            identified_push_service,
            service_ids: self.state.data.service_ids.clone(),
            message_sender: self.new_message_sender().await?,
            account_entropy_pool: self.account_entropy_pool().await?,
            registration_type: self.registration_type(),
            decrypted: self
                .store
                .decrypted()
                .await
                .unwrap_or_else(|error| {
                    error!(%error, "failed to load the messages decrypted and not handled");
                    Vec::new()
                })
                .into(),
            pending: VecDeque::new(),
            stored_packs,
            stored_packs_sender,
        };

        debug!("starting to consume incoming message stream");

        let incoming_messages_stream =
            futures::stream::unfold(receiver, |mut receiver| async move {
                let received = receiver.next().await?;
                Some((received, receiver))
            });

        Ok(Box::pin(
            // We use the returning of the async closure in take_until as a stop signal
            // if the future resolves *anything* the stream will end.
            incoming_messages_stream.take_until(refresh_registration_task),
        ))
    }
}

struct Receiver<S: Store, E> {
    store: S,
    identified_websocket: SignalWebSocket<websocket::Identified>,
    unidentified_websocket: SignalWebSocket<websocket::Unidentified>,
    envelopes: E,
    message_receiver: MessageReceiver,
    session_lock: SessionLock,
    trust_roots: Vec<PublicKey>,
    aci_address: ProtocolAddress,
    pni_address: ProtocolAddress,
    groups_manager: GroupsManager<GroupCredentialsCache>,
    identified_push_service: PushService,
    service_ids: ServiceIds,
    message_sender: MessageSender<S::AciStore>,
    account_entropy_pool: Option<AccountEntropyPool>,
    registration_type: RegistrationType,
    /// Decrypted and kept before the receiver stopped, but not handled: handled first.
    decrypted: VecDeque<(u64, Content)>,
    /// Told before the next envelope is read.
    pending: VecDeque<Received>,
    /// The ids of sticker packs installed elsewhere, once stored in the background.
    stored_packs: mpsc::UnboundedReceiver<Vec<u8>>,
    stored_packs_sender: mpsc::UnboundedSender<Vec<u8>>,
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
            let incoming =
                match future::select(self.stored_packs.next(), self.envelopes.next()).await {
                    Either::Left((Some(pack_id), _)) => {
                        return Some(Received::StickerPackInstalled { pack_id })
                    }
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
                    if self.account_entropy_pool.is_none() {
                        debug!(
                            "device does not have the needed keys; requesting from primary device"
                        );

                        let mut message_sender = self.message_sender.clone();
                        tokio::task::spawn_local(async move {
                            let result = message_sender
                                .send_sync_message(SyncMessage {
                                    content: Some(SyncContent::Request(sync_message::Request {
                                        r#type: Some(sync_message::request::Type::Keys.into()),
                                    })),
                                    ..SyncMessage::with_padding(&mut rand::rng())
                                })
                                .await;

                            if let Err(error) = result {
                                warn!(%error, "Error requesting keys from the primary device");
                            }
                        });
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

    /// Handles a decrypted content: stores it, and what else it asks for.
    async fn handle(&mut self, content: Content) -> Option<Received> {
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

        if let ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(SyncContent::Request(request)),
            ..
        }) = &content.body
        {
            self.answer(request.r#type()).await;
        }

        // contacts synchronization sent from the primary device (happens after linking, or on demand)
        if let ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(SyncContent::Contacts(contacts)),
            ..
        }) = &content.body
        {
            match self.message_receiver.retrieve_contacts(contacts).await {
                Ok(contacts) => {
                    info!("saving contacts");
                    for contact in contacts.filter_map(Result::ok) {
                        if let Err(error) = self.store.save_contact(&contact.into()).await {
                            warn!(%error, "failed to save contacts");
                            break;
                        }
                    }
                }
                Err(error) => {
                    warn!(%error, "failed to retrieve contacts");
                }
            }

            return Some(Received::Contacts);
        }

        // sticker pack operations
        if let ContentBody::SynchronizeMessage(SyncMessage {
            sticker_pack_operation,
            ..
        }) = &content.body
        {
            for operation in sticker_pack_operation {
                match operation.r#type() {
                    sticker_pack_operation::Type::Install => {
                        let store = self.store.clone();
                        let unidentified_websocket = self.unidentified_websocket.clone();
                        let operation = operation.clone();
                        let stored = self.stored_packs_sender.clone();

                        // download stickers in the background
                        tokio::spawn(async move {
                            match download_sticker_pack(store, unidentified_websocket, &operation)
                                .await
                            {
                                Ok(sticker_pack) => {
                                    debug!(
                                        "downloaded sticker pack: {} made by {}",
                                        sticker_pack.manifest.title, sticker_pack.manifest.author
                                    );
                                    // Fails only once the stream is gone.
                                    let _ = stored.unbounded_send(operation.pack_id().to_vec());
                                }
                                Err(error) => error!(%error, "failed to download sticker pack"),
                            }
                        });
                    }
                    sticker_pack_operation::Type::Remove => {
                        match self.store.remove_sticker_pack(operation.pack_id()).await {
                            Ok(was_present) => debug!(was_present, "removed stick pack"),
                            Err(error) => error!(%error, "failed to remove sticker pack"),
                        }
                    }
                }
            }
        }

        // key synchronization sent from the primary device
        if let ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(SyncContent::Keys(keys)),
            ..
        }) = &content.body
        {
            debug!("received key sync message");
            if self.registration_type == RegistrationType::Primary {
                warn!("received a key sync message as a primary device; ignoring")
            } else {
                match keys
                    .account_entropy_pool
                    .as_ref()
                    .map(|s| AccountEntropyPool::from_str(s))
                {
                    Some(Ok(aep)) => {
                        if let Err(error) = self.store.store_account_entropy_pool(Some(&aep)).await
                        {
                            error!(%error, "failed to store account entropy pool");
                        }
                        self.account_entropy_pool = Some(aep);
                    }
                    Some(Err(error)) => {
                        warn!(%error, "cannot convert account entropy pool from string")
                    }
                    None => {}
                }
            }
        }

        // The primary device told us to fetch stuff again from the storage service.
        if let ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(SyncContent::FetchLatest(fetch_latest)),
            ..
        }) = &content.body
        {
            if fetch_latest.r#type() == sync_message::fetch_latest::Type::StorageManifest {
                if let Err(error) = sync_groups_from_storage_service(
                    &self.store,
                    self.identified_push_service.clone(),
                    &mut self.groups_manager,
                )
                .await
                {
                    warn!(%error, "failed to sync groups from the storage service");
                }
            }
        }

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
                Err(error) => warn!(%error, "failed to update the group"),
            }
        }

        let kept = save_message(
            &mut self.store,
            &mut self.identified_websocket,
            &content,
            None,
        )
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

    /// Answers another device's sync request, in the background: the send needs this stream
    /// polled to go out.
    async fn answer(&self, request: RequestType) {
        let mut message_sender = self.message_sender.clone();
        match request {
            RequestType::Contacts => {
                let contacts = self
                    .store
                    .contacts()
                    .await
                    .map(|i| i.collect::<Result<Vec<_>, _>>().unwrap_or_default())
                    .unwrap_or_default();
                let aci = self.service_ids.aci();
                tokio::task::spawn_local(async move {
                    let result = message_sender
                        .send_contact_details(
                            &ServiceId::Aci(aci),
                            None,
                            contacts.into_iter().map(|c| ContactDetails {
                                number: c.phone_number.map(|p| p.to_string()),
                                aci: Some(c.uuid.to_string()),
                                aci_binary: Some(c.uuid.into_bytes().into()),
                                name: Some(c.name),
                                avatar: c.avatar.map(|a| contact_details::Avatar {
                                    content_type: Some(a.content_type),
                                    length: a.reader.len().try_into().ok(),
                                }),
                                expire_timer: Some(c.expire_timer),
                                expire_timer_version: Some(c.expire_timer_version),
                                inbox_position: None,
                            }),
                            false,
                            true,
                        )
                        .await;

                    if let Err(error) = result {
                        warn!(%error, "Error sending contact details to other devices");
                    }
                });
            }
            RequestType::Keys => {
                let account_entropy_pool = self
                    .account_entropy_pool
                    .as_ref()
                    .map(|aep| aep.to_string());
                tokio::task::spawn_local(async move {
                    let result = message_sender
                        .send_sync_message(SyncMessage {
                            content: Some(SyncContent::Keys(sync_message::Keys {
                                account_entropy_pool,
                                media_root_backup_key: None,
                            })),
                            ..SyncMessage::with_padding(&mut rand::rng())
                        })
                        .await;

                    if let Err(error) = result {
                        warn!(%error, "Error sending keys to other devices");
                    }
                });
            }
            RequestType::Blocked => {
                warn!("storing blocked user is not implemented yet! we will not report blocked users to the device requesting the sync.");
                tokio::task::spawn_local(async move {
                    let result = message_sender
                        .send_sync_message(SyncMessage {
                            content: Some(SyncContent::Blocked(sync_message::Blocked {
                                numbers: vec![],
                                acis: vec![],
                                acis_binary: vec![],
                                group_ids: vec![],
                            })),
                            ..SyncMessage::with_padding(&mut rand::rng())
                        })
                        .await;

                    if let Err(error) = result {
                        warn!(%error, "Error sending blocked contacts to other devices");
                    }
                });
            }
            t => {
                info!(type = ?t, "Got sync request of currently unhandled type")
            }
        }
    }
}

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
