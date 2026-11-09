use std::str::FromStr;

use futures::{future, Stream, StreamExt};
use libsignal_service::libsignal_account_keys::AccountEntropyPool;
use libsignal_service::{
    content::ContentBody,
    encrypt_device_name,
    groups_v2::{GroupsManager, InMemoryCredentialsCache},
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

use super::{
    download_sticker_pack, save_message, sync_groups_from_storage_service, upsert_group,
    MessageSender, Registered, RegistrationData, RegistrationType, ServiceCipher,
};
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
        struct StreamState<Receiver, Store, AciStore, PniStore> {
            store: Store,
            identified_websocket: SignalWebSocket<websocket::Identified>,
            unidentified_websocket: SignalWebSocket<websocket::Unidentified>,
            encrypted_messages: Receiver,
            message_receiver: MessageReceiver,
            service_cipher_aci: ServiceCipher<AciStore>,
            service_cipher_pni: ServiceCipher<PniStore>,
            groups_manager: GroupsManager<InMemoryCredentialsCache>,
            identified_push_service: PushService,
            service_ids: ServiceIds,
            message_sender: MessageSender<AciStore>,
            account_entropy_pool: Option<AccountEntropyPool>,
            registration_type: RegistrationType,
        }

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

        let init = StreamState {
            store: self.store.clone(),
            identified_websocket,
            unidentified_websocket: self.unidentified_websocket().await?,
            encrypted_messages: Box::pin(encrypted_messages.stream()),
            message_receiver: MessageReceiver::new(identified_push_service.clone()),
            service_cipher_aci: self.new_service_cipher_aci(),
            service_cipher_pni: self.new_service_cipher_pni(),
            groups_manager: Box::pin(self.groups_manager()).await?,
            identified_push_service,
            service_ids: self.state.data.service_ids.clone(),
            message_sender: self.new_message_sender().await?,
            account_entropy_pool: self.account_entropy_pool().await?,
            registration_type: self.registration_type(),
        };

        debug!("starting to consume incoming message stream");

        let incoming_messages_stream = futures::stream::unfold(init, |mut state| {
            async move {
                loop {
                    match state.encrypted_messages.next().await {
                        Some(Ok(Incoming::Envelope { envelope, ack })) => {
                            ack.ack();
                            let envelope = {
                                // the permit is released at the end of the block (impl Drop)
                                match envelope.parse_destination_service_id() {
                                    None => {
                                        warn!("Message has no destination service ID, dropping.");
                                        continue;
                                    }
                                    Some(ServiceId::Aci(_)) => {
                                        state
                                            .service_cipher_aci
                                            .open_envelope(envelope, &mut rand::rng())
                                            .await
                                    }
                                    Some(ServiceId::Pni(pni)) => {
                                        if pni == state.service_ids.pni()
                                            && envelope.parse_source_service_id().is_none()
                                        {
                                            warn!("Got a sealed sender message to our PNI? Invalid message, ignoring.");
                                            continue;
                                        }
                                        state
                                            .service_cipher_pni
                                            .open_envelope(envelope, &mut rng())
                                            .await
                                    }
                                }
                            };
                            match envelope {
                                Ok(Some(content)) => {
                                    if let ContentBody::DecryptionErrorMessage(e) = &content.body {
                                        error!(
                                            error = ?e,
                                            "got error decrypting a message"
                                        );
                                        return Some((
                                            Received::DecryptionError(content.metadata.sender),
                                            state,
                                        ));
                                    }

                                    if let ContentBody::SynchronizeMessage(SyncMessage {
                                        content: Some(SyncContent::Request(request)),
                                        ..
                                    }) = &content.body
                                    {
                                        use libsignal_service::content::sync_message::request::Type as RequestType;

                                        match request.r#type() {
                                            RequestType::Contacts => {
                                                let contacts = state
                                                    .store
                                                    .contacts()
                                                    .await
                                                    .map(|i| {
                                                        i.collect::<Result<Vec<_>, _>>()
                                                            .unwrap_or_default()
                                                    })
                                                    .unwrap_or_default();

                                                let mut message_sender =
                                                    state.message_sender.clone();
                                                let aci = state.service_ids.aci();
                                                tokio::task::spawn_local(async move {
                                                    let result = message_sender
                                                    .send_contact_details(
                                                        &ServiceId::Aci(aci),
                                                        None,
                                                        contacts.into_iter().map(|c| libsignal_service::sender::ContactDetails {
                                                            number: c.phone_number.map(|p| p.to_string()),
                                                            aci: Some(c.uuid.to_string()),
                                                            aci_binary: Some(c.uuid.into_bytes().into()),
                                                            name: Some(c.name),
                                                            avatar: c.avatar.map(|a| libsignal_service::proto::contact_details::Avatar {
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
                                                let mut message_sender =
                                                    state.message_sender.clone();
                                                let account_entropy_pool = state
                                                    .account_entropy_pool
                                                    .as_ref()
                                                    .map(|aep| aep.to_string());
                                                tokio::task::spawn_local(async move {
                                                    let result = message_sender.send_sync_message(SyncMessage {
                                                        content: Some(SyncContent::Keys(libsignal_service::content::sync_message::Keys {
                                                            account_entropy_pool,
                                                            media_root_backup_key: None,
                                                        })),
                                                        ..SyncMessage::with_padding(&mut rand::rng())
                                                    }).await;

                                                    if let Err(error) = result {
                                                        warn!(%error, "Error sending keys to other devices");
                                                    }
                                                });
                                            }
                                            RequestType::Blocked => {
                                                warn!("storing blocked user is not implemented yet! we will not report blocked users to the device requesting the sync.");
                                                let mut message_sender =
                                                    state.message_sender.clone();
                                                tokio::task::spawn_local(async move {
                                                    let result = message_sender.send_sync_message(SyncMessage {
                                                    content: Some(SyncContent::Blocked(libsignal_service::content::sync_message::Blocked {
                                                        numbers: vec![],
                                                        acis: vec![],
                                                        acis_binary: vec![],
                                                        group_ids: vec![],
                                                    })),
                                                    ..SyncMessage::with_padding(&mut rand::rng())
                                                }).await;

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

                                    // contacts synchronization sent from the primary device (happens after linking, or on demand)
                                    if let ContentBody::SynchronizeMessage(SyncMessage {
                                        content: Some(SyncContent::Contacts(contacts)),
                                        ..
                                    }) = &content.body
                                    {
                                        match state
                                            .message_receiver
                                            .retrieve_contacts(contacts)
                                            .await
                                        {
                                            Ok(contacts) => {
                                                info!("saving contacts");
                                                for contact in contacts.filter_map(Result::ok) {
                                                    if let Err(error) = state
                                                        .store
                                                        .save_contact(&contact.into())
                                                        .await
                                                    {
                                                        warn!(%error, "failed to save contacts");
                                                        break;
                                                    }
                                                }
                                            }
                                            Err(error) => {
                                                warn!(%error, "failed to retrieve contacts");
                                            }
                                        }

                                        return Some((Received::Contacts, state));
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
                                                    let store = state.store.clone();
                                                    let unidentified_websocket =
                                                        state.unidentified_websocket.clone();
                                                    let operation = operation.clone();

                                                    // download stickers in the background
                                                    tokio::spawn(async move {
                                                        match download_sticker_pack(
                                                            store,
                                                            unidentified_websocket,
                                                            &operation,
                                                        )
                                                        .await
                                                        {
                                                            Ok(sticker_pack) => {
                                                                debug!(
                                                                "downloaded sticker pack: {} made by {}",
                                                                sticker_pack.manifest.title,
                                                                sticker_pack.manifest.author
                                                            );
                                                            }
                                                            Err(error) => error!(
                                                                %error,
                                                                "failed to download sticker pack"
                                                            ),
                                                        }
                                                    });
                                                }
                                                sticker_pack_operation::Type::Remove => match state
                                                    .store
                                                    .remove_sticker_pack(operation.pack_id())
                                                    .await
                                                {
                                                    Ok(was_present) => {
                                                        debug!(was_present, "removed stick pack")
                                                    }
                                                    Err(error) => {
                                                        error!(
                                                            %error,
                                                            "failed to remove sticker pack"
                                                        )
                                                    }
                                                },
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
                                        if state.registration_type == RegistrationType::Primary {
                                            warn!("received a key sync message as a primary device; ignoring")
                                        } else {
                                            match keys
                                                .account_entropy_pool
                                                .as_ref()
                                                .map(|s| AccountEntropyPool::from_str(s))
                                            {
                                                Some(Ok(aep)) => {
                                                    if let Err(error) = state
                                                        .store
                                                        .store_account_entropy_pool(Some(&aep))
                                                        .await
                                                    {
                                                        error!(%error, "failed to store account entropy pool");
                                                    }
                                                    state.account_entropy_pool = Some(aep);
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
                                        if fetch_latest.r#type()
                                            == sync_message::fetch_latest::Type::StorageManifest
                                        {
                                            if let Err(error) = sync_groups_from_storage_service(
                                                &state.store,
                                                state.identified_push_service.clone(),
                                                &mut state.groups_manager,
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
                                                ..
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
                                                                ..
                                                            }),
                                                        ..
                                                    }),
                                                ..
                                            })),
                                        ..
                                    }) = &content.body
                                    {
                                        // there's two things to implement: the group metadata (fetched from HTTP API)
                                        // and the group changes, which are part of the protobuf messages
                                        // this means we kinda need our own internal representation of groups inside of presage?
                                        if let Ok(Some(group)) = upsert_group(
                                            &state.store,
                                            &mut state.groups_manager,
                                            master_key_bytes,
                                            revision,
                                        )
                                        .await
                                        {
                                            trace!(?group, "upserted group");
                                        }
                                    }

                                    if let Err(error) = save_message(
                                        &mut state.store,
                                        &mut state.identified_websocket,
                                        content.clone(),
                                        None,
                                    )
                                    .await
                                    {
                                        error!(%error, "error saving message to store");
                                    }

                                    return Some((Received::Content(Box::new(content)), state));
                                }
                                Ok(None) => {
                                    debug!("empty envelope, message will be skipped!")
                                }
                                Err(error) => {
                                    error!(%error, "error opening envelope, message will be skipped!");
                                    if let libsignal_service::prelude::ServiceError::SealedSenderDecryptionError(libsignal_service::cipher::SealedSenderDecryptionError { sender: Some(sender), .. }) = &error {
                                        if let Some(sender) = ServiceId::parse_from_service_id_string(sender.name()) {
                                            return Some((Received::DecryptionError(sender), state));
                                        }
                                    }
                                }
                            }
                        }
                        Some(Ok(Incoming::QueueEmpty)) => {
                            debug!("got empty queue");
                            if state.account_entropy_pool.is_none() {
                                debug!("device does not have the needed keys; requesting from primary device");

                                let mut message_sender = state.message_sender.clone();
                                tokio::task::spawn_local(async move {
                                    let result = message_sender
                                        .send_sync_message(SyncMessage {
                                            content: Some(SyncContent::Request(
                                                sync_message::Request {
                                                    r#type: Some(
                                                        sync_message::request::Type::Keys.into(),
                                                    ),
                                                },
                                            )),
                                            ..SyncMessage::with_padding(&mut rand::rng())
                                        })
                                        .await;

                                    if let Err(error) = result {
                                        warn!(%error, "Error sending blocked contacts to other devices");
                                    }
                                });
                            }
                            return Some((Received::QueueEmpty, state));
                        }
                        Some(Err(error)) => {
                            error!(%error, "unexpected error in message receiving loop")
                        }
                        None => return None,
                    }
                }
            }
        });

        Ok(Box::pin(
            // We use the returning of the async closure in take_until as a stop signal
            // if the future resolves *anything* the stream will end.
            incoming_messages_stream.take_until(refresh_registration_task),
        ))
    }
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
