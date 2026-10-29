use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::TimeZone;
use futures::{future, AsyncReadExt, Stream, StreamExt};
use libsignal_service::master_key::MasterKey;
use libsignal_service::prelude::SessionStoreExt;
use libsignal_service::protocol::{ProtocolAddress, PublicKey, SessionStore};
use libsignal_service::provisioning::ProvisioningSecrets;
use libsignal_service::session_lock::SessionLock;
use libsignal_service::{
    attachment_cipher::decrypt_in_place,
    cipher,
    configuration::{Endpoint, ServiceConfiguration, SignalServers},
    content::{Content, ContentBody, Metadata},
    encrypt_device_name,
    groups_v2::{
        decrypt_group, AccessRequired, GroupInviteLink, GroupJoinInfo, GroupsManager,
    },
    messagepipe::{Incoming, MessagePipe, ServiceCredentials},
    prelude::{phonenumber::PhoneNumber, MessageSenderError, ProtobufMessage, Uuid},
    profile_cipher::ProfileCipher,
    proto::{
        data_message::Delete,
        sync_message::{
            self, sticker_pack_operation, Content as SyncContent, StickerPackOperation,
        },
        AttachmentPointer, DataMessage, EditMessage, GroupContextV2, NullMessage, SyncMessage,
        Verified,
    },
    protocol::{
        Aci, DeviceId, IdentityKeyStore, SenderCertificate, ServiceId, ServiceIdKind, Username,
    },
    provisioning::ProvisioningError,
    push_service::{HttpAuthOverride, PushService, ServiceError, ServiceIds, DEFAULT_DEVICE_ID},
    receiver::MessageReceiver,
    sender::{AttachmentSpec, AttachmentUploadError},
    sticker_cipher::derive_key,
    unidentified_access::UnidentifiedAccess,
    utils::TryIntoE164,
    websocket::{
        self,
        account::{AccountAttributes, DeviceCapabilities, DeviceInfo, WhoAmIResponse},
        calling::TurnServer,
        SignalWebSocket,
    },
    zkgroup::{
        groups::{GroupMasterKey, GroupSecretParams},
        profiles::ProfileKey,
        GroupMasterKeyBytes,
    },
    AccountManager, Profile, ServiceIdExt,
};
use libsignal_service::{
    libsignal_account_keys::AccountEntropyPool, proto::addressable_message::Author,
};
use rand::rng;

use super::group_credentials::{GroupCredentialsCache, SharedGroupCredentials};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace, warn};
use url::Url;

use crate::model::contacts::Contact;
use crate::model::previews;
use crate::serde::serde_profile_key;
use crate::store::{
    ContentExt, ContentsStore, Sticker, StickerPack, StickerPackManifest, Store, Thread,
};
use crate::{model::groups::Group, AvatarBytes, Error, Manager};
use libsignal_service::master_key::StorageServiceKey;
use libsignal_service::proto::{manifest_record, storage_record};
use libsignal_service::StorageService;

pub use crate::model::messages::Received;

type ServiceCipher<S> = cipher::ServiceCipher<S>;
type MessageSender<S> = libsignal_service::prelude::MessageSender<S>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationType {
    Primary,
    Secondary,
}

/// Manager state when the client is registered and can send and receive messages from Signal
#[derive(Clone)]
pub struct Registered {
    pub(crate) identified_push_service: OnceLock<PushService>,
    pub(crate) unidentified_push_service: OnceLock<PushService>,
    pub(crate) identified_websocket: Arc<Mutex<Option<SignalWebSocket<websocket::Identified>>>>,
    pub(crate) unidentified_websocket: Arc<Mutex<Option<SignalWebSocket<websocket::Unidentified>>>>,
    pub(crate) unidentified_sender_certificate: Arc<Mutex<Option<SenderCertificate>>>,
    pub(crate) link_preview_client: OnceLock<reqwest::Client>,
    /// Shared by every cipher and sender of this account, and by its clones.
    pub(crate) session_lock: SessionLock,
    /// See [`Manager::set_automatic_link_previews`]; shared by the manager's clones.
    pub(crate) automatic_link_previews: Arc<AtomicBool>,
    /// See [`Manager::set_receive_stories`]; shared by the manager's clones.
    pub(crate) receive_stories: Arc<AtomicBool>,

    /// The account's group credentials, which every groups manager made shares.
    pub(crate) group_credentials: SharedGroupCredentials,

    pub(crate) data: Arc<RegistrationData>,
}

impl fmt::Debug for Registered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registered").finish_non_exhaustive()
    }
}

impl Registered {
    pub(crate) fn with_data(data: RegistrationData) -> Self {
        Self {
            identified_push_service: Default::default(),
            unidentified_push_service: Default::default(),
            identified_websocket: Default::default(),
            unidentified_websocket: Default::default(),
            unidentified_sender_certificate: Default::default(),
            link_preview_client: Default::default(),
            session_lock: Default::default(),
            automatic_link_previews: Arc::new(AtomicBool::new(true)),
            receive_stories: Arc::new(AtomicBool::new(false)),
            group_credentials: Default::default(),
            data: Arc::new(data),
        }
    }

    /// The text of `message` to fetch a link preview for, if it gets one automatically.
    fn automatic_link_preview_body<'a>(&self, message: &'a DataMessage) -> Option<&'a str> {
        if !self.automatic_link_previews.load(Ordering::Relaxed) || !message.preview.is_empty() {
            return None;
        }
        message.body.as_deref()
    }

    fn servers(&self) -> SignalServers {
        self.data.signal_servers.clone()
    }

    fn service_configuration(&self) -> ServiceConfiguration {
        self.servers().into()
    }

    pub fn device_id(&self) -> DeviceId {
        self.data
            .device_id
            .and_then(|d| d.try_into().ok())
            .unwrap_or(*DEFAULT_DEVICE_ID)
    }

    pub(crate) fn identified_push_service(&self) -> PushService {
        self.identified_push_service
            .get_or_init(|| crate::client::push_service(self.servers(), Some(self.credentials())))
            .clone()
    }

    pub(crate) fn credentials(&self) -> ServiceCredentials {
        ServiceCredentials {
            aci: Some(self.data.service_ids.aci),
            pni: Some(self.data.service_ids.pni),
            phonenumber: (&self.data.phone_number)
                .try_into_e164()
                .expect("valid phone number"),
            password: Some(self.data.password.clone()),
            device_id: self.data.device_id.and_then(|d| d.try_into().ok()),
        }
    }
}

/// Registration data like device name, and credentials to connect to Signal
#[derive(Serialize, Deserialize, Clone)]
pub struct RegistrationData {
    pub signal_servers: SignalServers,
    pub device_name: Option<String>,
    pub phone_number: PhoneNumber,
    #[serde(flatten)]
    pub service_ids: ServiceIds,
    pub(crate) password: String,
    pub device_id: Option<u32>,
    pub registration_id: u32,
    #[serde(default)]
    pub pni_registration_id: Option<u32>,
    #[serde(with = "serde_profile_key")]
    pub(crate) profile_key: ProfileKey,
    /// Decrypts the link-time message history archive. Single-use, so not persisted.
    #[serde(skip)]
    pub(crate) ephemeral_backup_key: Option<[u8; 32]>,
}

impl RegistrationData {
    /// Our own profile key
    pub fn profile_key(&self) -> ProfileKey {
        self.profile_key
    }

    /// The name of the device (if linked as secondary)
    pub fn device_name(&self) -> Option<&str> {
        self.device_name.as_deref()
    }

    /// Set right after [`Manager::link_secondary_device`][crate::Manager::link_secondary_device]
    /// if the primary device offered to transfer message history.
    pub fn ephemeral_backup_key(&self) -> Option<[u8; 32]> {
        self.ephemeral_backup_key
    }
}

impl<S> Manager<S, Registered> {
    /// Whether [`Self::send_message`] and [`Self::send_message_to_group`] give a data message
    /// without a preview one for its first link, as [`Self::link_preview`] does. On by default.
    ///
    /// Fetching the linked page reveals the user's IP address to its server. An app that leaves
    /// this to its user turns it off, and sets a preview from [`Self::link_preview`] itself when
    /// the user wants one. Applies to this manager's clones too.
    pub fn set_automatic_link_previews(&self, enabled: bool) {
        self.state
            .automatic_link_previews
            .store(enabled, Ordering::Relaxed);
    }

    /// Whether the server delivers stories to this device (`X-Signal-Receive-Stories`). Off by
    /// default: the server then drops every story sent to it, unread. An app that shows stories
    /// turns it on before it receives; it applies from the next connection on, and to this
    /// manager's clones too.
    pub fn set_receive_stories(&self, enabled: bool) {
        self.state.receive_stories.store(enabled, Ordering::Relaxed);
    }
}

impl<S: Store> Manager<S, Registered> {
    /// Loads a previously registered account from the implemented [Store].
    ///
    /// Returns a instance of [Manager] you can use to send & receive messages.
    pub async fn load_registered(store: S) -> Result<Self, Error<S::Error>> {
        let registration_data = store
            .load_registration_data()
            .await?
            .ok_or(Error::NotYetRegisteredError)?;

        let registered = Registered::with_data(registration_data);

        if let Some(sender_certificate) = store.sender_certificate().await? {
            registered
                .unidentified_sender_certificate
                .lock()
                .await
                .replace(sender_certificate);
        }

        Ok(Self {
            store,
            state: registered,
        })
    }

    /// Returns a handle to the [Store] implementation.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Returns a handle on the [RegistrationData].
    pub fn registration_data(&self) -> &RegistrationData {
        &self.state.data
    }

    /// The lock this manager and its clones take each session step under: a client that
    /// changes a session in the store itself (archiving one, say) takes a step too, so that
    /// it doesn't run into a decryption or a send.
    pub fn session_lock(&self) -> &SessionLock {
        &self.state.session_lock
    }

    /// Returns a clone of a cached push service (with credentials).
    ///
    /// If no service is yet cached, it will create and cache one. Public for requests presage
    /// doesn't make itself, such as asking for a sticker pack's upload forms.
    pub fn identified_push_service(&self) -> PushService {
        self.state.identified_push_service()
    }

    /// Returns a clone of a cached push service (without credentials).
    ///
    /// If no service is yet cached, it will create and cache one.
    fn unidentified_push_service(&self) -> PushService {
        self.state
            .unidentified_push_service
            .get_or_init(|| crate::client::push_service(self.state.servers(), None))
            .clone()
    }

    /// Returns the current identified websocket, or creates a new one
    ///
    /// A new one is created if the current websocket is closed, or if there is none yet.
    async fn identified_websocket(
        &self,
        require_unused: bool,
    ) -> Result<SignalWebSocket<websocket::Identified>, Error<S::Error>> {
        let mut identified_ws = self.state.identified_websocket.lock().await;
        match identified_ws
            .as_ref()
            .filter(|ws| !ws.is_closed())
            .filter(|ws| !(require_unused && ws.is_used()))
        {
            Some(ws) => Ok(ws.clone()),
            None => {
                let receive_stories = if self.state.receive_stories.load(Ordering::Relaxed) {
                    "true"
                } else {
                    "false"
                };
                let headers = &[("X-Signal-Receive-Stories", receive_stories)];
                let ws = self
                    .identified_push_service()
                    .ws(
                        "/v1/websocket/",
                        "/v1/keepalive",
                        headers,
                        Some(self.credentials()),
                    )
                    .await?;
                identified_ws.replace(ws.clone());
                info!("initialized identified websocket");

                Ok(ws)
            }
        }
    }

    /// Returns the current unidentified websocket, or creates a new one
    ///
    /// A new one is created if the current websocket is closed, or if there is none yet.
    async fn unidentified_websocket(
        &self,
    ) -> Result<SignalWebSocket<websocket::Unidentified>, Error<S::Error>> {
        let mut unidentified_ws = self.state.unidentified_websocket.lock().await;
        match unidentified_ws.as_ref().filter(|ws| !ws.is_closed()) {
            Some(ws) => Ok(ws.clone()),
            None => {
                let ws = self
                    .unidentified_push_service()
                    .ws("/v1/websocket/", "/v1/keepalive", &[], None)
                    .await?;
                unidentified_ws.replace(ws.clone());
                info!("initialized unidentified websocket");

                Ok(ws)
            }
        }
    }

    /// Request the primary device to encrypt & send all of its contacts.
    ///
    /// **Note**: If successful, the contacts are not yet received and stored, but will only be
    /// processed when they're received after polling on the
    pub async fn request_contacts(&mut self) -> Result<(), Error<S::Error>> {
        trace!("requesting contacts sync");
        let sync_message = SyncMessage {
            content: Some(SyncContent::Request(sync_message::Request {
                r#type: Some(sync_message::request::Type::Contacts.into()),
            })),
            ..SyncMessage::with_padding(&mut rand::rng())
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
            .await?;

        Ok(())
    }

    async fn sender_certificate(&self) -> Result<SenderCertificate, Error<S::Error>> {
        let needs_renewal = |sender_certificate: Option<&SenderCertificate>| -> bool {
            if sender_certificate.is_none() {
                return true;
            }

            let seconds_since_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();

            if let Some(expiration) = sender_certificate.and_then(|s| s.expiration().ok()) {
                expiration.epoch_millis() / 1000 <= seconds_since_epoch + 600
            } else {
                true
            }
        };

        let mut unidentified_sender_certificate =
            self.state.unidentified_sender_certificate.lock().await;
        if needs_renewal(unidentified_sender_certificate.as_ref()) {
            let sender_certificate = self
                .identified_websocket(false)
                .await?
                .get_uuid_only_sender_certificate()
                .await?;
            self.store
                .save_sender_certificate(&sender_certificate)
                .await?;
            unidentified_sender_certificate.replace(sender_certificate);
        }

        Ok(unidentified_sender_certificate
            .clone()
            .expect("logic error"))
    }

    /// For editing records without decoding them. `None` as for [`Self::storage_service`].
    pub async fn storage_access(
        &self,
    ) -> Result<
        Option<(
            libsignal_service::push_service::PushService,
            libsignal_service::master_key::StorageServiceKey,
        )>,
        Error<S::Error>,
    > {
        use libsignal_service::master_key::{MasterKey, StorageServiceKey};
        let Some(pool) = self.account_entropy_pool().await? else {
            return Ok(None);
        };
        let master_key =
            MasterKey::from_slice(&pool.derive_svr_key()).expect("master keys have 32 bytes");
        Ok(Some((
            self.identified_push_service(),
            StorageServiceKey::from_master_key(&master_key),
        )))
    }

    /// `None` until the primary device has sent the account entropy pool.
    pub async fn storage_service(
        &self,
    ) -> Result<Option<libsignal_service::StorageService>, Error<S::Error>> {
        let Some(pool) = self.account_entropy_pool().await? else {
            return Ok(None);
        };
        use libsignal_service::master_key::{MasterKey, StorageServiceKey};
        // The SVR key is the account's master key.
        let master_key =
            MasterKey::from_slice(&pool.derive_svr_key()).expect("master keys have 32 bytes");
        let key = StorageServiceKey::from_master_key(&master_key);
        let service =
            libsignal_service::StorageService::new(self.identified_push_service(), key).await?;
        Ok(Some(service))
    }

    async fn account_entropy_pool(&self) -> Result<Option<AccountEntropyPool>, Error<S::Error>> {
        let from_store = self.store().fetch_account_entropy_pool().await?;

        if let Some(key) = from_store {
            Ok(Some(key))
        } else if self.registration_type() == RegistrationType::Primary {
            let key = AccountEntropyPool::generate(&mut rand::rng());
            self.store().store_account_entropy_pool(Some(&key)).await?;
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }

    pub async fn submit_recaptcha_challenge(
        &self,
        token: &str,
        captcha: &str,
    ) -> Result<(), Error<S::Error>> {
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            None,
        );
        account_manager
            .submit_recaptcha_challenge(token, captcha)
            .await?;
        Ok(())
    }

    /// Fetches basic information on the registered device.
    pub async fn whoami(&self) -> Result<WhoAmIResponse, Error<S::Error>> {
        Ok(self.identified_websocket(false).await?.whoami().await?)
    }

    pub fn device_id(&self) -> DeviceId {
        self.state.device_id()
    }

    /// Fetches the profile (name, about, status emoji) of the registered user.
    pub async fn retrieve_profile(&mut self) -> Result<Profile, Error<S::Error>> {
        self.retrieve_profile_by_uuid(self.state.data.service_ids.aci, self.state.data.profile_key)
            .await
    }

    /// Fetches the profile of the provided user by UUID and profile key.
    pub async fn retrieve_profile_by_uuid(
        &mut self,
        aci: impl Into<Aci>,
        profile_key: ProfileKey,
    ) -> Result<Profile, Error<S::Error>> {
        let aci = aci.into();

        // Check if profile is cached.
        // TODO: Create a migration in the store removing all profiles.
        // TODO: Is there some way to know if this is outdated?
        if let Some(profile) = self
            .store
            .profile(aci.into(), profile_key)
            .await
            .ok()
            .flatten()
        {
            return Ok(profile);
        }

        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(profile_key),
        );

        let profile = account_manager.retrieve_profile(aci).await?;

        let _ = self
            .store
            .save_profile(aci.into(), profile_key, profile.clone())
            .await;
        Ok(profile)
    }

    /// Fetches the profile of `aci` from the server even when one is cached, and caches it:
    /// a new picture or name doesn't change the profile key, so the cached one may be out of
    /// date. A changed avatar is downloaded and cached too.
    pub async fn refresh_profile(
        &mut self,
        aci: impl Into<Aci>,
        profile_key: ProfileKey,
    ) -> Result<Profile, Error<S::Error>> {
        let aci = aci.into();
        let cached = self
            .store
            .profile(aci.into(), profile_key)
            .await
            .ok()
            .flatten();

        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(profile_key),
        );
        let profile = account_manager.retrieve_profile(aci).await?;
        let _ = self
            .store
            .save_profile(aci.into(), profile_key, profile.clone())
            .await;

        let avatar_changed =
            cached.as_ref().map(|cached| cached.avatar.as_ref()) != Some(profile.avatar.as_ref());
        if let Some(avatar) = profile.avatar.as_ref().filter(|_| avatar_changed) {
            let avatar = self.download_avatar(avatar, profile_key).await?;
            let _ = self
                .store
                .save_profile_avatar(aci.into(), profile_key, &avatar)
                .await;
        }
        Ok(profile)
    }

    /// Updates the user's profile information.
    pub async fn update_profile(
        &mut self,
        name: libsignal_service::profile_name::ProfileName<String>,
        about: Option<String>,
        emoji: Option<String>,
    ) -> Result<(), Error<S::Error>> {
        let aci = self.state.data.service_ids.aci();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );

        account_manager
            .upload_versioned_profile_without_avatar::<_, String>(
                aci,
                name,
                about,
                emoji,
                true, // retain_avatar
                &mut rand::rng(),
            )
            .await?;

        // Retrieve and save locally so we have the updated version
        let profile = account_manager.retrieve_profile(aci).await?;
        let _ = self
            .store
            .save_profile(aci.into(), self.state.data.profile_key, profile)
            .await;

        Ok(())
    }

    pub async fn retrieve_group_avatar(
        &mut self,
        context: GroupContextV2,
    ) -> Result<Option<AvatarBytes>, Error<S::Error>> {
        let master_key_bytes = context
            .master_key()
            .try_into()
            .expect("Master key bytes to be of size 32.");

        // Cached, and kept current by `upsert_group`; empty means the group has none.
        if let Some(avatar) = self
            .store
            .group_avatar(master_key_bytes)
            .await
            .ok()
            .flatten()
        {
            return Ok(Some(avatar).filter(|avatar| !avatar.is_empty()));
        }

        let mut gm = Box::pin(self.groups_manager()).await?;
        let Some(group) = upsert_group(
            &self.store,
            &mut gm,
            context.master_key(),
            &context.revision(),
        )
        .await?
        else {
            return Ok(None);
        };

        // Empty path means no avatar was set.
        if group.avatar.is_empty() {
            return Ok(None);
        }

        let avatar = gm
            .retrieve_avatar(
                &group.avatar,
                GroupSecretParams::derive_from_master_key(GroupMasterKey::new(master_key_bytes)),
            )
            .await?;
        if let Some(avatar) = &avatar {
            let _ = self.store.save_group_avatar(master_key_bytes, avatar).await;
        }
        Ok(avatar)
    }

    pub async fn retrieve_profile_avatar_by_uuid(
        &mut self,
        uuid: Uuid,
        profile_key: ProfileKey,
    ) -> Result<Option<AvatarBytes>, Error<S::Error>> {
        let profile =
            if let Some(profile) = self.store.profile(uuid, profile_key).await.ok().flatten() {
                profile
            } else {
                self.retrieve_profile_by_uuid(uuid, profile_key).await?
            };

        // A profile without one has none, whatever was cached before it was removed.
        let Some(avatar) = profile.avatar.as_ref() else {
            return Ok(None);
        };

        // Kept up to date by `refresh_profile`.
        if let Some(avatar) = self
            .store
            .profile_avatar(uuid, profile_key)
            .await
            .ok()
            .flatten()
        {
            return Ok(Some(avatar));
        }

        let avatar = self.download_avatar(avatar, profile_key).await?;
        let _ = self
            .store
            .save_profile_avatar(uuid, profile_key, &avatar)
            .await;
        Ok(Some(avatar))
    }

    /// Downloads and decrypts the profile avatar at the CDN path `avatar`.
    async fn download_avatar(
        &mut self,
        avatar: &str,
        profile_key: ProfileKey,
    ) -> Result<AvatarBytes, Error<S::Error>> {
        let mut websocket = self.unidentified_websocket().await?;

        let mut avatar_stream = websocket.retrieve_profile_avatar(avatar).await?;
        // 10MB is what Signal Android allocates
        let mut contents = Vec::with_capacity(10 * 1024 * 1024);
        let len = avatar_stream.read_to_end(&mut contents).await?;
        contents.truncate(len);

        let cipher = ProfileCipher::new(profile_key);
        Ok(cipher.decrypt_avatar(&contents)?)
    }

    async fn groups_manager(
        &self,
    ) -> Result<GroupsManager<GroupCredentialsCache>, Error<S::Error>> {
        let service_configuration = self.state.service_configuration();
        let server_public_params = service_configuration.zkgroup_server_public_params;

        let groups_credentials_cache = self.state.group_credentials.cache();
        let groups_manager = GroupsManager::new(
            self.state.data.service_ids.clone(),
            self.identified_push_service(),
            self.unidentified_websocket().await?,
            groups_credentials_cache,
            server_public_params,
        );

        Ok(groups_manager)
    }

    /// See [`sync_groups_from_storage_service`].
    pub(super) async fn sync_groups_from_storage_service(&self) -> Result<(), Error<S::Error>> {
        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        sync_groups_from_storage_service(
            &self.store,
            self.identified_push_service(),
            &mut groups_manager,
        )
        .await
    }

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
        struct StreamState<Receiver, Store, AciStore> {
            store: Store,
            identified_websocket: SignalWebSocket<websocket::Identified>,
            unidentified_websocket: SignalWebSocket<websocket::Unidentified>,
            encrypted_messages: Receiver,
            message_receiver: MessageReceiver,
            /// Decrypting takes it for the session step and keeping what it decrypted.
            session_lock: SessionLock,
            trust_roots: Vec<PublicKey>,
            aci_address: ProtocolAddress,
            pni_address: ProtocolAddress,
            /// Decrypted and kept, but not handled before the receiver stopped: handled first.
            decrypted: std::collections::VecDeque<(u64, Content)>,
            groups_manager: GroupsManager<GroupCredentialsCache>,
            identified_push_service: PushService,
            service_ids: ServiceIds,
            message_sender: MessageSender<AciStore>,
            account_entropy_pool: Option<AccountEntropyPool>,
            registration_type: RegistrationType,
            /// The ids of sticker packs installed elsewhere, once downloaded and stored in the
            /// background: what the stream says with [`Received::StickerPackInstalled`].
            stored_packs: futures::channel::mpsc::UnboundedReceiver<Vec<u8>>,
            stored_packs_sender: futures::channel::mpsc::UnboundedSender<Vec<u8>>,
        }

        /// Handles a decrypted content: stores it, and what else it asks for.
        async fn handle_content<St: Store, Receiver>(
            state: &mut StreamState<Receiver, St, St::AciStore>,
            content: Content,
        ) -> Option<Received> {
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
                use libsignal_service::content::sync_message::request::Type as RequestType;

                match request.r#type() {
                    RequestType::Contacts => {
                        let contacts = state
                            .store
                            .contacts()
                            .await
                            .map(|i| i.collect::<Result<Vec<_>, _>>().unwrap_or_default())
                            .unwrap_or_default();

                        let mut message_sender = state.message_sender.clone();
                        let aci = state.service_ids.aci();
                        tokio::task::spawn_local(async move {
                            let result = message_sender
                                .send_contact_details(
                                    &ServiceId::Aci(aci),
                                    None,
                                    contacts.into_iter().map(|c| {
                                        libsignal_service::sender::ContactDetails {
                                            number: c.phone_number.map(|p| p.to_string()),
                                            aci: Some(c.uuid.to_string()),
                                            aci_binary: Some(c.uuid.into_bytes().into()),
                                            name: Some(c.name),
                                            avatar: c.avatar.map(|a| {
                                                libsignal_service::proto::contact_details::Avatar {
                                                    content_type: Some(a.content_type),
                                                    length: a.reader.len().try_into().ok(),
                                                }
                                            }),
                                            expire_timer: Some(c.expire_timer),
                                            expire_timer_version: Some(c.expire_timer_version),
                                            inbox_position: None,
                                        }
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
                        let mut message_sender = state.message_sender.clone();
                        let account_entropy_pool = state
                            .account_entropy_pool
                            .as_ref()
                            .map(|aep| aep.to_string());
                        tokio::task::spawn_local(async move {
                            let result = message_sender
                                .send_sync_message(SyncMessage {
                                    content: Some(SyncContent::Keys(
                                        libsignal_service::content::sync_message::Keys {
                                            account_entropy_pool,
                                            media_root_backup_key: None,
                                        },
                                    )),
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
                        let mut message_sender = state.message_sender.clone();
                        tokio::task::spawn_local(async move {
                            let result = message_sender
                                .send_sync_message(SyncMessage {
                                    content: Some(SyncContent::Blocked(
                                        libsignal_service::content::sync_message::Blocked {
                                            numbers: vec![],
                                            acis: vec![],
                                            acis_binary: vec![],
                                            group_ids: vec![],
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
                match state.message_receiver.retrieve_contacts(contacts).await {
                    Ok(contacts) => {
                        info!("saving contacts");
                        for contact in contacts.filter_map(Result::ok) {
                            if let Err(error) = state.store.save_contact(&contact.into()).await {
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
                            let store = state.store.clone();
                            let unidentified_websocket = state.unidentified_websocket.clone();
                            let operation = operation.clone();
                            let stored = state.stored_packs_sender.clone();

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
                                        // Gone only with the stream.
                                        let _ = stored.unbounded_send(operation.pack_id().to_vec());
                                    }
                                    Err(error) => error!(
                                        %error,
                                        "failed to download sticker pack"
                                    ),
                                }
                            });
                        }
                        sticker_pack_operation::Type::Remove => {
                            match state.store.remove_sticker_pack(operation.pack_id()).await {
                                Ok(was_present) => {
                                    debug!(was_present, "removed stick pack")
                                }
                                Err(error) => {
                                    error!(
                                        %error,
                                        "failed to remove sticker pack"
                                    )
                                }
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
                if state.registration_type == RegistrationType::Primary {
                    warn!("received a key sync message as a primary device; ignoring")
                } else {
                    match keys
                        .account_entropy_pool
                        .as_ref()
                        .map(|s| AccountEntropyPool::from_str(s))
                    {
                        Some(Ok(aep)) => {
                            if let Err(error) =
                                state.store.store_account_entropy_pool(Some(&aep)).await
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
            // Handled after the session step: the network calls don't hold the session lock.
            if let ContentBody::SynchronizeMessage(SyncMessage {
                content: Some(SyncContent::FetchLatest(fetch_latest)),
                ..
            }) = &content.body
            {
                if fetch_latest.r#type() == sync_message::fetch_latest::Type::StorageManifest {
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

            Some(Received::Content(Box::new(content)))
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
        let (stored_packs_sender, stored_packs) = futures::channel::mpsc::unbounded();

        let init = StreamState {
            store: self.store.clone(),
            identified_websocket,
            unidentified_websocket: self.unidentified_websocket().await?,
            encrypted_messages: Box::pin(encrypted_messages.stream()),
            message_receiver: MessageReceiver::new(identified_push_service.clone()),
            session_lock: self.state.session_lock.clone(),
            trust_roots: self
                .state
                .service_configuration()
                .unidentified_sender_trust_roots,
            aci_address: ProtocolAddress::new(
                self.state.data.service_ids.aci().service_id_string(),
                self.state.device_id(),
            ),
            pni_address: ProtocolAddress::new(
                self.state.data.service_ids.pni().service_id_string(),
                self.state.device_id(),
            ),
            decrypted: self
                .store
                .decrypted()
                .await
                .unwrap_or_else(|error| {
                    error!(%error, "failed to load the messages decrypted and not handled");
                    Vec::new()
                })
                .into(),
            groups_manager: Box::pin(self.groups_manager()).await?,
            identified_push_service,
            service_ids: self.state.data.service_ids.clone(),
            message_sender: self.new_message_sender().await?,
            account_entropy_pool: self.account_entropy_pool().await?,
            registration_type: self.registration_type(),
            stored_packs,
            stored_packs_sender,
        };

        debug!("starting to consume incoming message stream");

        let incoming_messages_stream = futures::stream::unfold(init, |mut state| {
            async move {
                loop {
                    if let Some((id, content)) = state.decrypted.pop_front() {
                        debug!(
                            id,
                            "handling a message decrypted before the receiver stopped"
                        );
                        let received = handle_content(&mut state, content).await;
                        if let Err(error) = state.store.handled(id).await {
                            error!(%error, "failed to forget a handled message; it is handled again at the next start");
                        }
                        if let Some(received) = received {
                            return Some((received, state));
                        }
                        continue;
                    }
                    // A sticker pack stored in the background, or the next message.
                    let next = match future::select(
                        state.stored_packs.next(),
                        state.encrypted_messages.next(),
                    )
                    .await
                    {
                        future::Either::Left((Some(pack_id), _)) => future::Either::Left(pack_id),
                        future::Either::Left((None, incoming)) => {
                            future::Either::Right(incoming.await)
                        }
                        future::Either::Right((incoming, _)) => future::Either::Right(incoming),
                    };
                    let incoming = match next {
                        future::Either::Left(pack_id) => {
                            return Some((Received::StickerPackInstalled { pack_id }, state));
                        }
                        future::Either::Right(incoming) => incoming,
                    };
                    match incoming {
                        Some(Ok(Incoming::Envelope { envelope, ack })) => {
                            let received = async {
                                // Who sent an unsealed envelope, as the server authenticated it:
                                // names the sender of a message that fails to decrypt.
                                let source = envelope.parse_source_service_id();
                                // What a retry receipt names the message by.
                                let timestamp = envelope.client_timestamp();
                                let source_device = envelope.source_device_id();
                                let destination = envelope.parse_destination_service_id();
                                match destination {
                                    None => {
                                        warn!("Message has no destination service ID, dropping.");
                                        ack.ack();
                                        return None;
                                    }
                                    Some(ServiceId::Pni(pni))
                                        if pni == state.service_ids.pni()
                                            && envelope.parse_source_service_id().is_none() =>
                                    {
                                        warn!("Got a sealed sender message to our PNI? Invalid message, ignoring.");
                                        ack.ack();
                                        return None;
                                    }
                                    Some(_) => {}
                                }
                                // One session step, in one transaction: the session moves on and
                                // what the envelope held is kept, or neither. A receiver stopping
                                // before the commit leaves the envelope unacknowledged and the
                                // session as it was, to decrypt it again when it comes again.
                                let session_lock = state.session_lock.clone();
                                let step = session_lock.step().await;
                                let mut transaction = match state.store.transaction().await {
                                    Ok(transaction) => transaction,
                                    Err(error) => {
                                        error!(%error, "failed to begin a transaction; the envelope comes again");
                                        return None;
                                    }
                                };
                                // Their own session lock: this step holds the shared one.
                                let envelope = match destination {
                                    Some(ServiceId::Pni(_)) => {
                                        ServiceCipher::new(
                                            transaction.pni_protocol_store(),
                                            state.trust_roots.clone(),
                                            state.pni_address.clone(),
                                        )
                                        .open_envelope(envelope, &mut rng())
                                        .await
                                    }
                                    _ => {
                                        ServiceCipher::new(
                                            transaction.aci_protocol_store(),
                                            state.trust_roots.clone(),
                                            state.aci_address.clone(),
                                        )
                                        .open_envelope(envelope, &mut rng())
                                        .await
                                    }
                                };
                                let envelope = match envelope {
                                    Ok(Some(content)) => {
                                        match transaction.keep_decrypted(&content).await {
                                            Ok(id) => Ok(Some((Some(id), content))),
                                            Err(error) => {
                                                error!(%error, "failed to keep a decrypted message; the envelope comes again");
                                                return None;
                                            }
                                        }
                                    }
                                    Ok(None) => Ok(None),
                                    Err(error) => Err(error),
                                };
                                if let Err(error) = transaction.commit().await {
                                    error!(%error, "failed to commit a decrypted message; the envelope comes again");
                                    return None;
                                }
                                drop(step);
                                ack.ack();
                                match envelope {
                                    Ok(Some((id, content))) => {
                                        let received = handle_content(&mut state, content).await;
                                        if let Some(id) = id {
                                            if let Err(error) = state.store.handled(id).await {
                                                error!(%error, "failed to forget a handled message; it is handled again at the next start");
                                            }
                                        }
                                        return received;
                                    }
                                    Ok(None) => {
                                        debug!("empty envelope, message will be skipped!")
                                    }
                                    Err(error) => {
                                        error!(%error, "error opening envelope, message will be skipped!");
                                        use libsignal_service::cipher::SealedSenderDecryptionError;
                                        use libsignal_service::prelude::ServiceError;
                                        // A sealed sender is known once the certificate checked out;
                                        // an unsealed one is in the envelope.
                                        let failed = match error {
                                            ServiceError::SealedSenderDecryptionError(
                                                SealedSenderDecryptionError {
                                                    sender: Some(sender),
                                                    inner,
                                                },
                                            ) => ServiceId::parse_from_service_id_string(sender.name())
                                                .map(|id| (id, sender.device_id(), inner)),
                                            ServiceError::SignalProtocolError(error) => source
                                                .zip(DeviceId::try_from(source_device).ok())
                                                .map(|(sender, device)| (sender, device, error)),
                                            _ => None,
                                        };
                                        if let Some((sender, sender_device, error)) = failed {
                                            return Some(Received::DecryptionError {
                                                sender,
                                                sender_device,
                                                timestamp,
                                                error,
                                            });
                                        }
                                    }
                                }
                                None
                            }
                            .await;
                            if let Some(received) = received {
                                return Some((received, state));
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

    /// Uses Signal's SGX contact discovery service to resolve a phone number to its matching account identity
    #[cfg(feature = "cdsi")]
    pub async fn discover_contacts_by_phone_number<P: TryIntoE164>(
        &mut self,
        phone_numbers: impl IntoIterator<Item = P>,
    ) -> Result<Vec<(PhoneNumber, Option<ServiceId>)>, Error<S::Error>> {
        use libsignal_service::websocket::directory::LookupRequest;

        let mut ws = self.identified_websocket(false).await?;

        let lookup_request = LookupRequest {
            new_e164s: phone_numbers
                .into_iter()
                .filter_map(|p| p.try_into_e164().ok())
                .collect(),
            ..Default::default()
        };

        Ok(ws
            .discover_contacts(lookup_request)
            .await?
            .into_iter()
            .map(|(e164, service_id)| {
                use libsignal_service::utils::phonenumber_from_signal;
                (phonenumber_from_signal(&e164), service_id)
            })
            .collect())
    }

    /// Resolves a username (which has a text part and an additional random number) to its account identity
    /// for sending messages.
    pub async fn lookup_username(
        &mut self,
        username: &str,
    ) -> Result<Option<Aci>, Error<S::Error>> {
        let username = Username::new(username)?;
        let mut ws = self.unidentified_websocket().await?;
        let resolved_username = ws.look_up_username(&username).await?;
        Ok(resolved_username)
    }

    /// Sends a messages to the provided [ServiceId].
    /// The timestamp should be set to now and is used by Signal mobile apps
    /// to order messages later, and apply reactions.
    ///
    /// This method will automatically update the [DataMessage::expire_timer] if it is set to
    /// [None] such that the chat will keep the current expire timer. If the expire timer is set,
    /// it will be used as is, and the expire timer version will be incremented.
    pub async fn send_message(
        &mut self,
        recipient: impl Into<ServiceId>,
        message: impl Into<ContentBody>,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        let recipient = recipient.into();

        let online_only = false;
        // TODO: Populate this flag based on the recipient information
        //
        // Issue <https://github.com/whisperfish/presage/issues/252>
        let include_pni_signature = false;
        let thread = Thread::Contact(recipient);
        let mut content_body: ContentBody = message.into();

        self.restore_thread_timer(&thread, &mut content_body).await;
        self.fetch_link_previews(&mut content_body).await;

        let sender_certificate = self.sender_certificate().await?;
        let unidentified_access = self
            .store
            .profile_key(&recipient)
            .await?
            .map(|profile_key| UnidentifiedAccess {
                key: profile_key.derive_access_key().to_vec(),
                certificate: sender_certificate.clone(),
            })
            .or_else(|| story_access(&content_body, &sender_certificate));

        // we need to put our profile key in DataMessage
        if let ContentBody::DataMessage(message) = &mut content_body {
            message
                .profile_key
                .get_or_insert(self.state.data.profile_key().get_bytes().to_vec());
            message.required_protocol_version = Some(0);
        }

        ensure_data_message_timestamp(&mut content_body, timestamp);

        let mut sent = self
            .new_message_sender()
            .await?
            .send_message(
                &recipient,
                unidentified_access.as_ref(),
                content_body.clone(),
                timestamp,
                include_pni_signature,
                online_only,
            )
            .await;
        if sent.as_ref().is_err_and(websocket_closed) {
            warn!("websocket closed while sending; retrying on a new connection");
            sent = self
                .new_message_sender()
                .await?
                .send_message(
                    &recipient,
                    unidentified_access.as_ref(),
                    content_body.clone(),
                    timestamp,
                    include_pni_signature,
                    online_only,
                )
                .await;
        }
        sent?;

        // save the message
        let content = Content {
            metadata: Metadata {
                sender: self.state.data.service_ids.aci().into(),
                sender_device: self.state.device_id(),
                destination: recipient,
                server_guid: None,
                client_timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                // Note: Currently no way to get the timestamp the server received the message; just use our timestamp as a fallback.
                server_timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                needs_receipt: false,
                unidentified_sender: false,
                was_plaintext: false,
                pni_verified: None,
            },
            body: content_body,
        };

        let mut identified_websocket = self.identified_websocket(false).await?;
        save_message(
            &mut self.store,
            &mut identified_websocket,
            content,
            Some(thread),
        )
        .await?;

        Ok(())
    }

    /// Fetches a preview (title, description, image) for the first link in `body`, and
    /// uploads its image as an attachment, ready to be set as the `preview` of the
    /// `DataMessage` sending `body`.
    ///
    /// Returns `None` if `body` has no link to preview.
    ///
    /// This fetches the linked page, which reveals the user's IP address to its server.
    pub async fn link_preview(
        &self,
        body: &str,
    ) -> Result<Option<libsignal_service::proto::Preview>, Error<S::Error>> {
        let client = match self.state.link_preview_client.get() {
            Some(client) => client,
            None => {
                let client = previews::client_builder()
                    .build()
                    .map_err(previews::Error::from)?;
                self.state.link_preview_client.get_or_init(|| client)
            }
        };
        let Some(content) = previews::generate_preview_from_message(body, client).await? else {
            return Ok(None);
        };

        // the preview is still useful without its image
        let image = match previews::build_preview_image(&content) {
            Some((spec, bytes)) => match self.upload_attachment(spec, bytes).await {
                Ok(Ok(pointer)) => Some(pointer),
                Ok(Err(error)) => {
                    warn!(%error, "failed to upload link preview image");
                    None
                }
                Err(error) => {
                    warn!(%error, "failed to upload link preview image");
                    None
                }
            },
            None => None,
        };

        Ok(Some(libsignal_service::proto::Preview {
            url: content.url,
            title: content.title,
            image,
            description: content.description,
            date: content.date,
        }))
    }

    /// Sets a preview of the first link of a data message that has no preview yet, unless
    /// [automatic link previews](Self::set_automatic_link_previews) are off.
    async fn fetch_link_previews(&self, content_body: &mut ContentBody) {
        let ContentBody::DataMessage(message) = content_body else {
            return;
        };
        let Some(body) = self.state.automatic_link_preview_body(message) else {
            return;
        };
        match self.link_preview(body).await {
            Ok(preview) => message.preview.extend(preview),
            Err(error) => warn!(%error, "failed to build link preview, sending without"),
        }
    }

    /// Uploads one attachment prior to linking them in a message.
    pub async fn upload_attachment(
        &self,
        spec: AttachmentSpec,
        contents: Vec<u8>,
    ) -> Result<Result<AttachmentPointer, AttachmentUploadError>, Error<S::Error>> {
        Ok(self
            .new_message_sender()
            .await?
            .upload_attachment(spec, contents, &mut rng())
            .await)
    }

    /// Uploads attachments prior to linking them in a message.
    pub async fn upload_attachments(
        &self,
        attachments: Vec<(AttachmentSpec, Vec<u8>)>,
    ) -> Result<Vec<Result<AttachmentPointer, AttachmentUploadError>>, Error<S::Error>> {
        if attachments.is_empty() {
            return Ok(Vec::new());
        }
        let sender = self.new_message_sender().await?;
        let upload = future::join_all(attachments.into_iter().map(move |(spec, contents)| {
            let mut sender = sender.clone();
            async move { sender.upload_attachment(spec, contents, &mut rng()).await }
        }));
        Ok(upload.await)
    }

    /// Members without a known profile key are invited. Returns the master key and the
    /// timestamp of the message telling the members.
    pub async fn create_group(
        &mut self,
        title: &str,
        members: &[Aci],
    ) -> Result<([u8; 32], u64), Error<S::Error>> {
        use libsignal_service::groups_v2::{
            AccessControl, AccessRequired, GroupMemberCandidate, GroupOperations,
        };
        use libsignal_service::zkgroup::groups::{GroupMasterKey, GroupSecretParams};

        let master_key: [u8; 32] = rand::random();
        let operations = GroupOperations::new(GroupSecretParams::derive_from_master_key(
            GroupMasterKey::new(master_key),
        ));
        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        let server_public_params = groups_manager.server_public_params().clone();
        let own = self.state.data.service_ids.aci();
        let own_credential = self
            .profile_key_credential(own, self.state.data.profile_key(), &server_public_params)
            .await?;
        let mut candidates = Vec::new();
        for member in members.iter().filter(|m| **m != own) {
            let credential = match self.store.profile_key(&(*member).into()).await? {
                Some(key) => self
                    .profile_key_credential(*member, key, &server_public_params)
                    .await
                    .inspect_err(|error| warn!(%error, "no profile key credential; inviting"))
                    .ok(),
                None => None,
            };
            candidates.push(GroupMemberCandidate {
                service_id: (*member).into(),
                credential,
            });
        }
        // Signal's defaults for new groups.
        let access = AccessControl {
            attributes: AccessRequired::Member,
            members: AccessRequired::Member,
            add_from_invite_link: AccessRequired::Unsatisfiable,
            member_label: AccessRequired::Member,
        };
        let group = operations
            .encrypt_group_with_credentials(
                title,
                None,
                None,
                Some(&access),
                &own_credential,
                &candidates,
                &server_public_params,
                String::new(),
                &mut rng(),
            )
            .map_err(|e| Error::ServiceError(e.into()))?;
        groups_manager
            .create_group(&mut rng(), &master_key, group)
            .await?;
        upsert_group(&self.store, &mut groups_manager, &master_key, &0).await?;
        let message = DataMessage {
            group_v2: Some(GroupContextV2 {
                master_key: Some(master_key.to_vec()),
                revision: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let recipients: Vec<ServiceId> = members
            .iter()
            .copied()
            .filter(|m| *m != own)
            .map(ServiceId::Aci)
            .collect();
        let timestamp = Self::now();
        self.send_to_members(&master_key, &recipients, message, timestamp)
            .await?;
        Ok((master_key, timestamp))
    }

    /// Returns the timestamp of the message telling the members. Retried on a 409 conflict,
    /// as Signal's apps do.
    pub async fn change_group(
        &mut self,
        master_key: &[u8; 32],
        change: GroupEdit,
    ) -> Result<u64, Error<S::Error>> {
        use libsignal_service::groups_v2::GroupOperations;
        use libsignal_service::zkgroup::groups::{GroupMasterKey, GroupSecretParams};
        const ATTEMPTS: usize = 3;

        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        let operations = GroupOperations::new(GroupSecretParams::derive_from_master_key(
            GroupMasterKey::new(*master_key),
        ));
        let own = self.state.data.service_ids.aci();
        let pni = self.state.data.service_ids.pni();
        let leaving = matches!(change, GroupEdit::Leave | GroupEdit::DeclineInvitation);
        // Uploaded once, whatever the attempts below.
        let avatar_key = match &change {
            GroupEdit::Avatar(avatar) if avatar.is_empty() => Some(String::new()),
            GroupEdit::Avatar(avatar) => Some(
                groups_manager
                    .upload_avatar(&mut rng(), master_key, avatar)
                    .await?,
            ),
            _ => None,
        };
        let mut attempt = 0;
        let (group, revision, mut told, signed) = loop {
            attempt += 1;
            // The change must build on the latest revision.
            let Some(group) =
                upsert_group(&self.store, &mut groups_manager, master_key, &u32::MAX).await?
            else {
                return Err(Error::UnknownGroup);
            };
            let (actions, told) = self
                .group_change_actions(
                    &groups_manager,
                    &operations,
                    &group,
                    change.clone(),
                    avatar_key.clone(),
                )
                .await?;
            let revision = actions.version;
            match groups_manager
                .modify_group(&mut rng(), master_key, actions)
                .await
            {
                Ok(signed) => break (group, revision, told, signed),
                Err(error) if is_conflict(&error) && attempt < ATTEMPTS => {
                    debug!(
                        attempt,
                        "the group changed meanwhile; building the change again"
                    );
                }
                Err(error) => return Err(error.into()),
            }
        };
        // After leaving, the server no longer shows us the group: update our copy here.
        if leaving {
            let mut left = group;
            left.members.retain(|m| m.aci != own);
            left.pending_members
                .retain(|m| m.uuid != Uuid::from(own) && m.uuid != Uuid::from(pni));
            left.revision = revision;
            self.store.save_group(*master_key, left).await?;
        } else {
            upsert_group(&self.store, &mut groups_manager, master_key, &revision).await?;
        }
        if let GroupEdit::Avatar(avatar) = &change {
            self.store.save_group_avatar(*master_key, avatar).await?;
        }
        let message = DataMessage {
            group_v2: Some(GroupContextV2 {
                master_key: Some(master_key.to_vec()),
                revision: Some(revision),
                group_change: Some(libsignal_service::prelude::ProtobufMessage::encode_to_vec(
                    &signed,
                )),
            }),
            ..Default::default()
        };
        told.retain(|member| *member != ServiceId::Aci(own));
        told.sort();
        told.dedup();
        let timestamp = Self::now();
        self.send_to_members(master_key, &told, message, timestamp)
            .await?;
        Ok(timestamp)
    }

    /// The actions, and who is told: members and invitees before the change, plus those added.
    async fn group_change_actions(
        &self,
        groups_manager: &GroupsManager<GroupCredentialsCache>,
        operations: &libsignal_service::groups_v2::GroupOperations,
        group: &Group,
        change: GroupEdit,
        avatar_key: Option<String>,
    ) -> Result<
        (
            libsignal_service::proto::group_change::Actions,
            Vec<ServiceId>,
        ),
        Error<S::Error>,
    > {
        use libsignal_service::groups_v2::{GroupInviteLink, Role};
        use libsignal_service::proto::group_change::Actions;
        let decoding =
            |e| Error::ServiceError(libsignal_service::push_service::ServiceError::from(e));
        let own = self.state.data.service_ids.aci();
        let pni = self.state.data.service_ids.pni();
        let invited_as = invited_as(group, own, pni);
        let mut actions = Actions {
            version: group.revision + 1,
            ..Default::default()
        };
        let mut told = told_of_changes(group, own, pni);
        match change {
            GroupEdit::Title(title) => {
                actions.modify_title =
                    Some(operations.build_modify_title_action(&title, &mut rng()));
            }
            GroupEdit::Description(description) => {
                actions.modify_description =
                    Some(operations.build_modify_description_action(&description, &mut rng()));
            }
            GroupEdit::Avatar(_) => {
                actions.modify_avatar =
                    Some(operations.build_modify_avatar_action(avatar_key.unwrap_or_default()));
            }
            GroupEdit::Timer(seconds) => {
                actions.modify_disappearing_message_timer = Some(
                    operations.build_modify_disappearing_messages_timer_action(seconds, &mut rng()),
                );
            }
            GroupEdit::AddMembers(members) => {
                let server_public_params = groups_manager.server_public_params().clone();
                for member in members {
                    // Only an ACI with a profile key we have can be added outright.
                    let credential = match member {
                        ServiceId::Aci(aci) => match self.store.profile_key(&member).await? {
                            Some(key) => self
                                .profile_key_credential(aci, key, &server_public_params)
                                .await
                                .ok(),
                            None => None,
                        },
                        ServiceId::Pni(_) => None,
                    };
                    match credential {
                        Some(credential) => actions.add_members.push(
                            operations.build_add_member_action_with_credential(
                                &credential,
                                Role::Default,
                                &server_public_params,
                            ),
                        ),
                        None => actions.add_members_pending_profile_key.push(
                            operations
                                .build_add_pending_member_action(member, own, Role::Default)
                                .map_err(decoding)?,
                        ),
                    }
                    told.push(member);
                }
            }
            GroupEdit::RemoveMember(member) => {
                actions.delete_members.push(
                    operations
                        .build_remove_member_action(member)
                        .map_err(decoding)?,
                );
            }
            GroupEdit::SetAdmin(member, admin) => {
                let role = if admin {
                    Role::Administrator
                } else {
                    Role::Default
                };
                actions.modify_member_roles.push(
                    operations
                        .build_modify_member_role_action(member, role)
                        .map_err(decoding)?,
                );
            }
            GroupEdit::Leave => {
                actions.delete_members.push(
                    operations
                        .build_remove_member_action(own)
                        .map_err(decoding)?,
                );
            }
            GroupEdit::AcceptInvitation => {
                use libsignal_service::proto::group_change::actions::{
                    PromoteMemberPendingPniAciProfileKeyAction,
                    PromoteMemberPendingProfileKeyAction,
                };
                let invited_as = invited_as.ok_or(Error::NotInvited)?;
                // The server takes who we are and our profile key from the presentation.
                let server_public_params = groups_manager.server_public_params().clone();
                let credential = self
                    .profile_key_credential(own, self.state.data.profile_key, &server_public_params)
                    .await?;
                let presentation =
                    operations.create_member_presentation(&server_public_params, &credential);
                match invited_as {
                    ServiceId::Aci(_) => actions.promote_members_pending_profile_key.push(
                        PromoteMemberPendingProfileKeyAction {
                            presentation,
                            ..Default::default()
                        },
                    ),
                    // Invited by phone number: joining tells them our ACI too.
                    ServiceId::Pni(_) => actions.promote_members_pending_pni_aci_profile_key.push(
                        PromoteMemberPendingPniAciProfileKeyAction {
                            presentation,
                            ..Default::default()
                        },
                    ),
                }
            }
            GroupEdit::DeclineInvitation => {
                let invited_as = invited_as.ok_or(Error::NotInvited)?;
                actions.delete_members_pending_profile_key.push(
                    operations
                        .build_remove_pending_member_action(invited_as)
                        .map_err(decoding)?,
                );
            }
            GroupEdit::InviteLinkAccess(access) => {
                actions.modify_add_from_invite_link_access =
                    Some(operations.build_modify_invite_link_access_action(access));
                if access != AccessRequired::Unsatisfiable && group.invite_link_password.is_empty()
                {
                    actions.modify_invite_link_password =
                        Some(operations.build_modify_invite_link_password_action(
                            GroupInviteLink::new_password(&mut rng()),
                        ));
                }
            }
            GroupEdit::ResetInviteLink => {
                actions.modify_invite_link_password =
                    Some(operations.build_modify_invite_link_password_action(
                        GroupInviteLink::new_password(&mut rng()),
                    ));
            }
            GroupEdit::ApproveRequest(aci) => {
                actions.promote_members_pending_admin_approval.push(
                    operations
                        .build_promote_requesting_member_action(aci, Role::Default)
                        .map_err(decoding)?,
                );
                told.push(ServiceId::Aci(aci));
            }
            GroupEdit::DenyRequest(aci) => {
                actions.delete_members_pending_admin_approval.push(
                    operations
                        .build_remove_requesting_member_action(aci)
                        .map_err(decoding)?,
                );
            }
        }
        Ok((actions, told))
    }

    /// What a group shows to whoever has its invite link, and whether we asked to join
    /// already.
    pub async fn group_join_info(
        &mut self,
        link: &GroupInviteLink,
    ) -> Result<GroupJoinInfo, Error<S::Error>> {
        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        Ok(groups_manager.group_join_info(&mut rng(), link).await?)
    }

    /// Joins a group through its invite link, or asks to where administrators approve
    /// members. Retried on a 409 conflict, as Signal's apps do.
    pub async fn join_group(
        &mut self,
        link: &GroupInviteLink,
    ) -> Result<GroupJoin, Error<S::Error>> {
        use libsignal_service::groups_v2::GroupOperations;
        use libsignal_service::proto::group_change::Actions;
        const ATTEMPTS: usize = 3;

        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        let server_public_params = groups_manager.server_public_params().clone();
        let operations = GroupOperations::new(GroupSecretParams::derive_from_master_key(
            GroupMasterKey::new(link.master_key),
        ));
        let own = self.state.data.service_ids.aci();
        let credential = self
            .profile_key_credential(own, self.state.data.profile_key, &server_public_params)
            .await?;
        let mut attempt = 0;
        let (info, change) = loop {
            attempt += 1;
            let info = groups_manager.group_join_info(&mut rng(), link).await?;
            if info.pending_admin_approval {
                break (info, None);
            }
            let mut actions = Actions {
                version: info.version + 1,
                ..Default::default()
            };
            let member = match info.add_from_invite_link {
                AccessRequired::Any => {
                    actions.add_members.push(
                        operations
                            .build_join_from_invite_link_action(&credential, &server_public_params),
                    );
                    true
                }
                AccessRequired::Administrator => {
                    actions.add_members_pending_admin_approval.push(
                        operations.build_request_to_join_action(&credential, &server_public_params),
                    );
                    false
                }
                _ => return Err(Error::InviteLinkClosed),
            };
            let revision = actions.version;
            match groups_manager
                .modify_group_from_invite_link(&mut rng(), link, actions)
                .await
            {
                Ok(signed) => break (info, Some((signed, revision, member))),
                Err(error) if is_conflict(&error) && attempt < ATTEMPTS => {
                    debug!(attempt, "the group changed meanwhile; joining again");
                }
                Err(error) => return Err(error.into()),
            }
        };
        let Some((signed, revision, true)) = change else {
            // Not a member: the server shows us nothing more until we are let in. The members of
            // a group we were in stay as we have them, to tell them we asked.
            let known = self.store.group(link.master_key).await?;
            let (members, pending_members) = known
                .map(|known| (known.members, known.pending_members))
                .unwrap_or_default();
            let group = Group {
                title: info.title,
                avatar: info.avatar.clone(),
                disappearing_messages_timer: None,
                access_control: Some(crate::model::groups::AccessControl {
                    attributes: AccessRequired::Member,
                    members: AccessRequired::Member,
                    add_from_invite_link: info.add_from_invite_link,
                    member_label: AccessRequired::Member,
                }),
                revision: info.version,
                members,
                pending_members,
                requesting_members: vec![crate::model::groups::RequestingMember {
                    aci: own,
                    profile_key: self.state.data.profile_key,
                    timestamp: Self::now(),
                }],
                invite_link_password: link.password.clone(),
                description: info.description_text,
            };
            let mut group = group;
            let avatar = if info.avatar.is_empty() {
                // None any more: a picture cached from before we left would stay, as later
                // fetches find no picture on either side, and nothing to refresh.
                Some(Vec::new())
            } else {
                match groups_manager
                    .retrieve_avatar(&info.avatar, operations.group_secret_params)
                    .await
                {
                    Ok(Some(avatar)) => Some(avatar),
                    // Not cached: leave the path out, so the next fetch of the group gets it.
                    Ok(None) => {
                        group.avatar = String::new();
                        None
                    }
                    Err(error) => {
                        warn!(%error, "failed to fetch the group's avatar");
                        group.avatar = String::new();
                        None
                    }
                }
            };
            let told = told_of_changes(&group, own, self.state.data.service_ids.pni());
            self.store.save_group(link.master_key, group).await?;
            // After the group: its picture refers to it, and a group asked to join for the first
            // time isn't stored before.
            if let Some(avatar) = avatar {
                self.store
                    .save_group_avatar(link.master_key, &avatar)
                    .await?;
            }
            if let Some((signed, revision, _)) = change {
                self.tell_of_change(&link.master_key, &told, revision, &signed)
                    .await?;
            }
            return Ok(GroupJoin::Requested);
        };
        let Some(group) = upsert_group(
            &self.store,
            &mut groups_manager,
            &link.master_key,
            &u32::MAX,
        )
        .await?
        else {
            return Err(Error::UnknownGroup);
        };
        let told: Vec<ServiceId> = group
            .members
            .iter()
            .map(|m| ServiceId::Aci(m.aci))
            .filter(|m| *m != ServiceId::Aci(own))
            .collect();
        let timestamp = self
            .tell_of_change(&link.master_key, &told, revision, &signed)
            .await?;
        Ok(GroupJoin::Joined { timestamp })
    }

    /// Sends a signed change of a group to `told`; returns the message's timestamp.
    async fn tell_of_change(
        &mut self,
        master_key: &[u8; 32],
        told: &[ServiceId],
        revision: u32,
        signed: &libsignal_service::proto::GroupChange,
    ) -> Result<u64, Error<S::Error>> {
        let message = DataMessage {
            group_v2: Some(GroupContextV2 {
                master_key: Some(master_key.to_vec()),
                revision: Some(revision),
                group_change: Some(libsignal_service::prelude::ProtobufMessage::encode_to_vec(
                    signed,
                )),
            }),
            ..Default::default()
        };
        let timestamp = Self::now();
        self.send_to_members(master_key, told, message, timestamp)
            .await?;
        Ok(timestamp)
    }

    /// Withdraws the request made with [`Self::join_group`].
    pub async fn cancel_join_request(
        &mut self,
        master_key: &[u8; 32],
    ) -> Result<(), Error<S::Error>> {
        use libsignal_service::groups_v2::GroupOperations;
        use libsignal_service::proto::group_change::Actions;

        let Some(group) = self.store.group(*master_key).await? else {
            return Err(Error::UnknownGroup);
        };
        let link = GroupInviteLink {
            master_key: *master_key,
            password: group.invite_link_password,
        };
        let own = self.state.data.service_ids.aci();
        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        let info = groups_manager.group_join_info(&mut rng(), &link).await?;
        let mut cancelled = None;
        if info.pending_admin_approval {
            let operations = GroupOperations::new(GroupSecretParams::derive_from_master_key(
                GroupMasterKey::new(*master_key),
            ));
            let mut actions = Actions {
                version: info.version + 1,
                ..Default::default()
            };
            actions.delete_members_pending_admin_approval.push(
                operations
                    .build_remove_requesting_member_action(own)
                    .map_err(|e| Error::ServiceError(e.into()))?,
            );
            let revision = actions.version;
            let signed = groups_manager
                .modify_group_from_invite_link(&mut rng(), &link, actions)
                .await?;
            cancelled = Some((signed, revision));
        }
        // Read again: receiving may have replaced the group meanwhile.
        let Some(mut group) = self.store.group(*master_key).await? else {
            return Err(Error::UnknownGroup);
        };
        group.requesting_members.retain(|m| m.aci != own);
        let told = told_of_changes(&group, own, self.state.data.service_ids.pni());
        self.store.save_group(*master_key, group).await?;
        if let Some((signed, revision)) = cancelled {
            self.tell_of_change(master_key, &told, revision, &signed)
                .await?;
        }
        Ok(())
    }

    /// Fetches the group from the server whatever revision is stored, and stores it; an
    /// error (403) if we are not in it.
    pub async fn fetch_group(&mut self, master_key: &[u8; 32]) -> Result<Group, Error<S::Error>> {
        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        let avatar_path = self.store.group(*master_key).await?.map(|g| g.avatar);
        fetch_group(&self.store, &mut groups_manager, *master_key, avatar_path).await?;
        self.store
            .group(*master_key)
            .await?
            .ok_or(Error::UnknownGroup)
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_millis() as u64
    }

    async fn profile_key_credential(
        &self,
        aci: Aci,
        profile_key: ProfileKey,
        server_public_params: &libsignal_service::zkgroup::ServerPublicParams,
    ) -> Result<libsignal_service::zkgroup::profiles::ExpiringProfileKeyCredential, Error<S::Error>>
    {
        let mut websocket = self.identified_websocket(false).await?;
        Ok(websocket
            .retrieve_expiring_profile_key_credential(
                &mut rng(),
                aci,
                profile_key,
                server_public_params,
            )
            .await?)
    }

    /// For group changes, whose audience isn't the group as it is now. Failures are only
    /// logged: the change is already made.
    async fn send_to_members(
        &mut self,
        master_key: &[u8; 32],
        members: &[ServiceId],
        message: DataMessage,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        let mut content_body: ContentBody = message.into();
        ensure_data_message_timestamp(&mut content_body, timestamp);
        let mut sender = self.new_message_sender().await?;
        let sender_certificate = self.sender_certificate().await?;
        let mut recipients = Vec::new();
        for member in members {
            let unidentified_access =
                self.store
                    .profile_key(member)
                    .await?
                    .map(|profile_key| UnidentifiedAccess {
                        key: profile_key.derive_access_key().to_vec(),
                        certificate: sender_certificate.clone(),
                    });
            recipients.push((*member, unidentified_access, false));
        }
        let results = sender
            .send_message_to_group(recipients, content_body.clone(), timestamp, false)
            .await;
        for result in results {
            match result {
                Ok(_) | Err(MessageSenderError::NotFound { .. }) => {}
                Err(error) => warn!(%error, "failed to tell a member of a group change"),
            }
        }
        let own = self.state.data.service_ids.aci();
        let at = chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap();
        let content = Content {
            metadata: Metadata {
                sender: own.into(),
                destination: own.into(),
                sender_device: self.state.device_id(),
                server_guid: None,
                client_timestamp: at,
                server_timestamp: at,
                needs_receipt: false,
                unidentified_sender: false,
                was_plaintext: false,
                pni_verified: None,
            },
            body: content_body,
        };
        self.store
            .save_message(&Thread::Group(*master_key), content)
            .await?;
        Ok(())
    }

    /// Sends one message in a group (v2). The `master_key_bytes` is required to have 32 elements.
    ///
    /// This method will automatically update the [DataMessage::expire_timer] if it is set to
    /// [None] such that the chat will keep the current expire timer.
    pub async fn send_message_to_group(
        &mut self,
        master_key_bytes: &[u8],
        message: impl Into<ContentBody>,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        let mut content_body = message.into();
        let master_key_bytes = master_key_bytes
            .try_into()
            .expect("Master key bytes to be of size 32.");
        let thread = Thread::Group(master_key_bytes);

        self.restore_thread_timer(&thread, &mut content_body).await;
        self.fetch_link_previews(&mut content_body).await;
        ensure_data_message_timestamp(&mut content_body, timestamp);

        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        let Some(group) =
            upsert_group(&self.store, &mut groups_manager, &master_key_bytes, &0).await?
        else {
            return Err(Error::UnknownGroup);
        };

        let sender_certificate = self.sender_certificate().await?;
        let mut recipients = Vec::new();
        for member in group
            .members
            .into_iter()
            .filter(|m| m.aci != self.state.data.service_ids.aci())
        {
            let unidentified_access = self
                .store
                .profile_key(&member.aci.into())
                .await?
                .map(|profile_key| UnidentifiedAccess {
                    key: profile_key.derive_access_key().to_vec(),
                    certificate: sender_certificate.clone(),
                })
                .or_else(|| story_access(&content_body, &sender_certificate));
            let include_pni_signature = false;
            recipients.push((
                member.aci.into(),
                unidentified_access,
                include_pni_signature,
            ));
        }

        let online_only = false;
        let mut results = self
            .new_message_sender()
            .await?
            .send_message_to_group(&recipients, content_body.clone(), timestamp, online_only)
            .await;
        let again: Vec<_> = recipients
            .iter()
            .zip(&results)
            .filter(|(_, result)| result.as_ref().is_err_and(websocket_closed))
            .map(|(recipient, _)| recipient.clone())
            .collect();
        if !again.is_empty() {
            warn!(
                recipients = again.len(),
                "websocket closed while sending to the group; retrying on a new connection"
            );
            let mut retried = self
                .new_message_sender()
                .await?
                .send_message_to_group(&again, content_body.clone(), timestamp, online_only)
                .await
                .into_iter();
            for result in results
                .iter_mut()
                .filter(|result| result.as_ref().is_err_and(websocket_closed))
            {
                *result = retried.next().expect("one result per retried recipient");
            }
        }

        // TODO: Handle the NotFound error in the future by removing all sessions to this UUID and marking it as unregistered, not sending any messages to this contact anymore.
        results
            .into_iter()
            .find(|res| match res {
                Ok(_) => false,
                // Ignore any NotFound errors, those mean that e.g. some contact in a group deleted his account.
                Err(MessageSenderError::NotFound { service_id }) => {
                    debug!(service_id = %service_id.service_id_string(), "recipient not found, skipping sent message result");
                    false
                }
                // return first error if any
                Err(_) => true,
            })
            .transpose()?;

        let content = Content {
            metadata: Metadata {
                sender: self.state.data.service_ids.aci().into(),
                destination: self.state.data.service_ids.aci().into(),
                sender_device: self.state.device_id(),
                server_guid: None,
                client_timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                // Note: Currently no way to get the timestamp the server received the message; just use our timestamp as a fallback.
                server_timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                needs_receipt: false, // TODO: this is just wrong
                unidentified_sender: false,
                was_plaintext: false,
                pni_verified: None,
            },
            body: content_body,
        };

        let mut identified_websocket = self.identified_websocket(false).await?;
        save_message(
            &mut self.store,
            &mut identified_websocket,
            content,
            Some(thread),
        )
        .await?;

        Ok(())
    }

    async fn restore_thread_timer(&mut self, thread: &Thread, content_body: &mut ContentBody) {
        let store_expire_timer = self.store.expire_timer(thread).await.unwrap_or_default();

        if let ContentBody::DataMessage(DataMessage {
            expire_timer: ref mut timer,
            expire_timer_version: ref mut version,
            ..
        }) = content_body
        {
            if timer.is_none() {
                *timer = store_expire_timer.and_then(|(t, _)| if t == 0 { None } else { Some(t) });
                *version = Some(store_expire_timer.map(|(_, v)| v).unwrap_or_default());
            } else {
                *version = Some(store_expire_timer.map(|(_, v)| v).unwrap_or_default() + 1);
            }
        }
    }

    /// Clears all sessions established with [recipient](ServiceId).
    pub async fn clear_sessions(&self, recipient: &ServiceId) -> Result<(), Error<S::Error>> {
        use libsignal_service::session_store::SessionStoreExt;
        let _step = self.state.session_lock.step().await;
        self.store
            .aci_protocol_store()
            .delete_all_sessions(recipient)
            .await?;
        self.store
            .pni_protocol_store()
            .delete_all_sessions(recipient)
            .await?;
        Ok(())
    }

    /// Downloads and decrypts a single attachment.
    pub async fn get_attachment(
        &self,
        attachment_pointer: &AttachmentPointer,
    ) -> Result<Vec<u8>, Error<S::Error>> {
        let expected_digest = attachment_pointer
            .digest
            .as_ref()
            .ok_or_else(|| Error::UnexpectedAttachmentChecksum)?;

        let mut service = self.identified_push_service();
        let mut attachment_stream = service.get_attachment(attachment_pointer).await?;

        let plaintext_len = attachment_pointer.size.and_then(|len| len.try_into().ok());

        // We need the whole file for the crypto to check out
        let mut ciphertext = Vec::with_capacity(plaintext_len.unwrap_or(0));
        let size_bytes = attachment_stream
            .stream
            .read_to_end(&mut ciphertext)
            .await?;
        trace!(size_bytes, "downloaded encrypted attachment");

        let digest = sha2::Sha256::digest(&ciphertext);
        if &digest[..] != expected_digest {
            return Err(Error::UnexpectedAttachmentChecksum);
        }

        let key: [u8; 64] = attachment_pointer.key().try_into()?;

        // Offload decryption of large attachments to another thread.
        // Chose arbitrary threshold here.
        const DECRYPT_IN_THREAD_THRESHOLD: usize = 100 * 1024;
        if ciphertext.len() > DECRYPT_IN_THREAD_THRESHOLD {
            ciphertext = tokio::task::spawn_blocking(move || {
                decrypt_in_place(key, &mut ciphertext).map(|_| ciphertext)
            })
            .await
            .expect("decryption in another thread")?;
        } else {
            decrypt_in_place(key, &mut ciphertext)?;
        };

        if let Some(len) = plaintext_len {
            if len < ciphertext.len() {
                // remove padding
                ciphertext.truncate(len);
            }
        }

        Ok(ciphertext)
    }

    /// Gets the metadata of a sticker
    pub async fn sticker_metadata(
        &mut self,
        pack_id: &[u8],
        sticker_id: u32,
    ) -> Result<Option<Sticker>, Error<S::Error>> {
        Ok(self.store.sticker_pack(pack_id).await?.and_then(|pack| {
            pack.manifest
                .stickers
                .iter()
                .find(|&x| x.id == sticker_id)
                .cloned()
        }))
    }

    /// Installs a sticker pack and notifies other registered devices
    pub async fn install_sticker_pack(
        &mut self,
        pack_id: &[u8],
        pack_key: &[u8],
    ) -> Result<(), Error<S::Error>> {
        let sticker_pack_operation = StickerPackOperation {
            pack_id: Some(pack_id.to_vec()),
            pack_key: Some(pack_key.to_vec()),
            r#type: Some(sticker_pack_operation::Type::Install as i32),
        };

        let unidentified_websocket = self.unidentified_websocket().await?;
        download_sticker_pack(
            self.store.clone(),
            unidentified_websocket,
            &sticker_pack_operation,
        )
        .await?;

        // Sync the change with the other devices
        let sync_message = SyncMessage {
            sticker_pack_operation: vec![sticker_pack_operation],
            ..Default::default()
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
            .await?;

        Ok(())
    }

    /// Removes an installed sticker pack
    pub async fn remove_sticker_pack(
        &mut self,
        pack_id: &[u8],
        pack_key: &[u8],
    ) -> Result<(), Error<S::Error>> {
        // Sync the change with the other clients
        let sync_message = SyncMessage {
            sticker_pack_operation: vec![StickerPackOperation {
                pack_id: Some(pack_id.to_vec()),
                pack_key: Some(pack_key.to_vec()), // The pack key might not be neccesary in the message
                r#type: Some(sticker_pack_operation::Type::Remove as i32),
            }],
            ..Default::default()
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
            .await?;

        self.store.remove_sticker_pack(pack_id).await?;

        Ok(())
    }

    pub async fn send_session_reset(
        &mut self,
        recipient: &ServiceId,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        trace!(recipient = %recipient.service_id_string(), "resetting session for address");

        let mut store = self.store.aci_protocol_store();
        let step = self.state.session_lock.step().await;

        // Archive all sessions with all receiver devices.
        // Note that the "get_sub_device_sessions" does not include the main device, therefore add it.
        // Note that deleting the session is not equivalent to archiving:
        // If we deleted the session, we would also delete the information on the list of devices the peer has, failing message sending.
        for device in store
            .get_sub_device_sessions(recipient)
            .await?
            .into_iter()
            .chain(vec![*DEFAULT_DEVICE_ID])
        {
            let address = recipient
                .aci()
                .expect("Recipient to be given as ACI")
                .to_protocol_address(device)
                .expect("Could not construct protocol address from recipient");
            if let Some(mut session) = store.load_session(&address).await? {
                session.archive_current_state()?;
                store.store_session(&address, &session).await?;
            }
        }
        drop(step);

        // TODO: Signal Android also deletes entries in some sender_key_shared table; we don't have such a table yet.
        // Does not seem necessary though.

        // Send a null message.
        let message = NullMessage::generate(&mut rand::rng());
        self.send_message(*recipient, message, timestamp).await?;

        Ok(())
    }

    /// Records a finished call in the thread with the peer of `event` and tells our other
    /// devices about it, so their call logs agree. Returns the stored content.
    pub async fn send_call_event(
        &mut self,
        event: sync_message::CallEvent,
    ) -> Result<Content, Error<S::Error>> {
        let sync_message = SyncMessage {
            content: Some(SyncContent::CallEvent(event.clone())),
            ..SyncMessage::with_padding(&mut rand::rng())
        };
        self.new_message_sender()
            .await?
            .send_sync_message(sync_message.clone())
            .await?;

        let aci = self.state.data.service_ids.aci();
        // Filed under the start of the call.
        let timestamp = event
            .timestamp
            .and_then(|ts| chrono::Utc.timestamp_millis_opt(ts as i64).single())
            .unwrap_or_else(chrono::Utc::now);
        let content = Content {
            metadata: Metadata {
                sender: aci.into(),
                sender_device: self.state.device_id(),
                destination: aci.into(),
                server_guid: None,
                client_timestamp: timestamp,
                server_timestamp: timestamp,
                needs_receipt: false,
                unidentified_sender: false,
                was_plaintext: false,
                pni_verified: None,
            },
            body: ContentBody::SynchronizeMessage(sync_message),
        };

        let mut identified_websocket = self.identified_websocket(false).await?;
        save_message(
            &mut self.store,
            &mut identified_websocket,
            content.clone(),
            None,
        )
        .await?;
        Ok(content)
    }

    /// Fetches short-lived TURN credentials for 1:1 calls.
    pub async fn calling_relays(&self) -> Result<Vec<TurnServer>, Error<S::Error>> {
        Ok(self
            .identified_websocket(false)
            .await?
            .get_calling_relays()
            .await?)
    }

    fn credentials(&self) -> ServiceCredentials {
        self.state.credentials()
    }

    /// Creates a new message sender.
    async fn new_message_sender(&self) -> Result<MessageSender<S::AciStore>, Error<S::Error>> {
        let identified_websocket = self.identified_websocket(false).await?;
        let unidentified_websocket = self.unidentified_websocket().await?;

        let aci_protocol_store = self.store.aci_protocol_store();
        let aci_identity_keypair = aci_protocol_store.get_identity_key_pair().await?;
        let pni_identity_keypair = self
            .store
            .pni_protocol_store()
            .get_identity_key_pair()
            .await?;

        Ok(MessageSender::new(
            identified_websocket,
            unidentified_websocket,
            self.identified_push_service(),
            self.new_service_cipher_aci(),
            aci_protocol_store,
            self.state.data.service_ids.aci,
            self.state.data.service_ids.pni,
            aci_identity_keypair,
            Some(pni_identity_keypair),
            self.state.device_id(),
        ))
    }

    fn new_service_cipher_aci(&self) -> ServiceCipher<S::AciStore> {
        ServiceCipher::new(
            self.store.aci_protocol_store(),
            self.state
                .service_configuration()
                .unidentified_sender_trust_roots,
            ProtocolAddress::new(
                self.state.data.service_ids.aci().service_id_string(),
                self.state.device_id(),
            ),
        )
        .with_session_lock(self.state.session_lock.clone())
    }

    /// Returns the title of a thread (contact or group).
    pub async fn thread_title(&self, thread: &Thread) -> Result<String, Error<S::Error>> {
        match thread {
            Thread::Contact(service_id) => {
                let contact = match self.store.contact_by_id(service_id).await {
                    Ok(contact) => contact,
                    Err(error) => {
                        info!(%error, service_id =% service_id.service_id_string(), "error getting contact by id");
                        None
                    }
                };
                Ok(match contact {
                    Some(contact) => contact.name,
                    None => service_id.service_id_string(),
                })
            }
            Thread::Group(id) => match self.store.group(*id).await? {
                Some(group) => Ok(group.title),
                None => Ok("".to_string()),
            },
        }
    }

    /// Returns how this client was registered, either as a primary or secondary device.
    pub fn registration_type(&self) -> RegistrationType {
        if self.state.data.device_name.is_some() {
            RegistrationType::Secondary
        } else {
            RegistrationType::Primary
        }
    }

    /// As a primary device, link a secondary device.
    pub async fn link_secondary(&mut self, secondary: Url) -> Result<(), Error<S::Error>> {
        // XXX: What happens if secondary device? Possible to use static typing to make this method call impossible in that case?
        if self.registration_type() != RegistrationType::Primary {
            return Err(Error::NotPrimaryDevice);
        }

        let credentials = self.credentials();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );

        account_manager
            .link_device(
                &mut rand::rng(),
                secondary,
                &self.store.aci_protocol_store(),
                &self.store.pni_protocol_store(),
                ProvisioningSecrets {
                    credentials,
                    account_entropy_pool: self
                        .account_entropy_pool()
                        .await?
                        .expect("Primary device to always have an account entropy pool"),
                    ephemeral_backup_key: None,
                    media_root_backup_key: None,
                    // presage keeps no read-receipt setting; Signal's clients start with them on.
                    read_receipts: Some(true),
                },
            )
            .await?;
        Ok(())
    }

    /// As a primary device, unlink a secondary device.
    pub async fn unlink_secondary(
        &self,
        device_id: impl TryInto<DeviceId>,
    ) -> Result<(), Error<S::Error>> {
        // secondary devices can only unlink themselves, see `unlink_self`
        if self.registration_type() != RegistrationType::Primary {
            return Err(Error::NotPrimaryDevice);
        }
        self.identified_websocket(false)
            .await?
            .unlink_device(device_id.try_into().map_err(|_| Error::InvalidDeviceId)?)
            .await?;
        Ok(())
    }

    /// As a primary device, list all the devices (including the current device).
    pub async fn devices(&self) -> Result<Vec<DeviceInfo>, Error<S::Error>> {
        let aci_protocol_store = self.store.aci_protocol_store();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );

        Ok(account_manager.linked_devices(&aci_protocol_store).await?)
    }

    /// Removes this linked device from the account, e.g. before linking again.
    pub async fn unlink_self(&self) -> Result<(), Error<S::Error>> {
        if self.registration_type() == RegistrationType::Primary {
            return Err(Error::NotSecondaryDevice);
        }
        self.identified_websocket(false)
            .await?
            .unlink_device(self.device_id())
            .await?;
        Ok(())
    }

    /// Waits up to `timeout` for the primary device to upload the history archive; `Ok(None)`
    /// if it hasn't yet. Keep `timeout` well below the HTTP client's 65 seconds.
    pub async fn transfer_archive(
        &self,
        timeout: std::time::Duration,
    ) -> Result<Option<TransferArchive>, Error<S::Error>> {
        let response = self
            .identified_push_service()
            .request(
                reqwest::Method::GET,
                Endpoint::service(format!(
                    "/v1/devices/transfer_archive?timeout={}",
                    timeout.as_secs().max(1)
                )),
                HttpAuthOverride::NoOverride,
            )?
            .send()
            .await
            .map_err(ServiceError::from)?;
        match response.status() {
            reqwest::StatusCode::NO_CONTENT => Ok(None),
            reqwest::StatusCode::OK => {
                let body = response.bytes().await.map_err(ServiceError::from)?;
                let archive: TransferArchiveResponse = serde_json::from_slice(&body)?;
                Ok(Some(archive.into()))
            }
            status => Err(ServiceError::UnhandledResponseCode {
                status,
                body: response.text().await.unwrap_or_default(),
            }
            .into()),
        }
    }

    /// Update the name of this device.
    pub async fn update_device_name(&mut self, name: &str) -> Result<(), Error<S::Error>> {
        let aci = self.state.data.service_ids.aci;
        let aci_protocol_store = self.store.aci_protocol_store();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );
        account_manager
            .update_device_name(
                self.device_id(),
                name,
                aci.into(),
                &aci_protocol_store,
                &mut rng(),
            )
            .await?;
        Ok(())
    }
}

/// See [`Manager::transfer_archive`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferArchive {
    /// Download from `attachments/{key}` on CDN `cdn`.
    Uploaded { cdn: u32, key: String },
    /// The user asked to try linking again.
    RelinkRequested,
    /// The upload failed and the user chose to continue without history.
    ContinueWithoutUpload,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TransferArchiveResponse {
    Uploaded { cdn: u32, key: String },
    Error { error: TransferArchiveError },
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TransferArchiveError {
    RelinkRequested,
    ContinueWithoutUpload,
}

impl From<TransferArchiveResponse> for TransferArchive {
    fn from(response: TransferArchiveResponse) -> Self {
        match response {
            TransferArchiveResponse::Uploaded { cdn, key } => Self::Uploaded { cdn, key },
            TransferArchiveResponse::Error {
                error: TransferArchiveError::RelinkRequested,
            } => Self::RelinkRequested,
            TransferArchiveResponse::Error {
                error: TransferArchiveError::ContinueWithoutUpload,
            } => Self::ContinueWithoutUpload,
        }
    }
}

/// Set the timestamp in any DataMessage so it matches its envelope's
/// The websocket's task ended before the request went out; a new connection can carry it.
fn websocket_closed(error: &MessageSenderError) -> bool {
    matches!(
        error,
        MessageSenderError::ServiceError(
            libsignal_service::push_service::ServiceError::WsClosing { .. }
        )
    )
}

fn ensure_data_message_timestamp(content_body: &mut ContentBody, timestamp: u64) {
    match content_body {
        ContentBody::DataMessage(message) => {
            message.timestamp = Some(timestamp);
        }
        ContentBody::EditMessage(EditMessage {
            data_message: Some(data_message),
            ..
        }) => {
            data_message.timestamp = Some(timestamp);
        }
        ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    message: Some(data_message),
                    ..
                })),
            ..
        }) => {
            data_message.timestamp = Some(timestamp);
        }
        _ => (),
    }
}

async fn sync_groups_from_storage_service<S: Store>(
    store: &S,
    push_service: PushService,
    groups_manager: &mut GroupsManager<GroupCredentialsCache>,
) -> Result<(), Error<S::Error>> {
    const READ_CHUNK: usize = 100;

    // The account entropy pool is the source of the master key: a linked device that got it in a
    // key sync, and a primary, have it without a stored master key.
    let master_key = match store.fetch_account_entropy_pool().await? {
        Some(aep) => MasterKey::from_slice(aep.derive_svr_key().as_slice()).ok(),
        None => store.fetch_master_key().await?,
    }
    .ok_or(Error::MissingKeyError("master_key".into()))?;
    let storage_key = StorageServiceKey::from_master_key(&master_key);
    let storage = StorageService::new(push_service, storage_key).await?;

    let manifest = storage.manifest().await?;
    let group_ids: Vec<Vec<u8>> = manifest
        .identifiers
        .iter()
        .filter(|id| id.r#type() == manifest_record::identifier::Type::Groupv2)
        .map(|id| id.raw.clone())
        .collect();
    debug!(
        count = group_ids.len(),
        "groups listed in the storage service"
    );

    for chunk in group_ids.chunks(READ_CHUNK) {
        let records = match storage
            .read_items(chunk.to_vec(), Some(&manifest.record_ikm))
            .await
        {
            Ok(records) => records,
            Err(error) => {
                warn!(%error, "failed to read group records from the storage service");
                continue;
            }
        };
        for record in records {
            let Some(storage_record::Record::GroupV2(record)) = record.record else {
                continue;
            };
            if let Err(error) = save_unknown_group(store, groups_manager, &record.master_key).await
            {
                warn!(%error, "failed to fetch group listed in the storage service");
            }
        }
    }
    Ok(())
}

/// Incoming messages keep known groups current, so only unknown ones are fetched.
async fn save_unknown_group<S: Store>(
    store: &S,
    groups_manager: &mut GroupsManager<GroupCredentialsCache>,
    master_key_bytes: &[u8],
) -> Result<(), Error<S::Error>> {
    let master_key: GroupMasterKeyBytes = master_key_bytes.try_into()?;
    if store.group(master_key).await?.is_some() || store.is_group_left(master_key).await? {
        return Ok(());
    }
    match groups_manager
        .fetch_encrypted_group(&mut rand::rng(), master_key_bytes)
        .await
    {
        Ok(encrypted_group) => {
            let group = decrypt_group(master_key_bytes, encrypted_group)?;
            store.save_group(master_key, group).await?;
        }
        // The group server refuses groups the account has left or was only invited to.
        Err(libsignal_service::prelude::ServiceError::Unauthorized) => {
            debug!("not a member of a group listed in the storage service");
            store.mark_group_left(master_key).await?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn upsert_group<S: Store>(
    store: &S,
    groups_manager: &mut GroupsManager<GroupCredentialsCache>,
    master_key_bytes: &[u8],
    revision: &u32,
) -> Result<Option<Group>, Error<S::Error>> {
    let master_key: [u8; 32] = master_key_bytes.try_into()?;
    let (upsert_group, avatar_path) = match store.group(master_key).await {
        Ok(Some(group)) => {
            debug!(group_name =% group.title, "loaded group from local db");
            (group.revision < *revision, Some(group.avatar))
        }
        Ok(None) => (true, None),
        Err(error) => {
            warn!(%error, "failed to retrieve group from local db");
            (true, None)
        }
    };

    if upsert_group {
        debug!("fetching and saving group");
        let mut fetched = fetch_group(store, groups_manager, master_key, avatar_path.clone()).await;
        // Once more if the connection failed: nothing fetches the group again until its next
        // message, and until then it stays as it was (a member who left, still listed). Not if
        // the server answered: a refusal (we aren't a member) would be the same again.
        if fetched
            .as_ref()
            .is_err_and(|error| matches!(error, Error::ServiceError(error) if transient(error)))
        {
            if let Err(error) = &fetched {
                warn!(error = %Causes(error), "failed to fetch encrypted group, fetching it again");
            }
            fetched = fetch_group(store, groups_manager, master_key, avatar_path).await;
        }
        if let Err(error) = fetched {
            warn!(error = %Causes(&error), "failed to fetch encrypted group");
        }
    }

    Ok(store.group(master_key_bytes.try_into()?).await?)
}

/// Whether `error` is the connection's, not the server's answer: worth sending again.
fn transient(error: &ServiceError) -> bool {
    matches!(
        error,
        ServiceError::Http(_) | ServiceError::Timeout { .. } | ServiceError::IO(_)
    )
}

/// An error with its causes, each after a colon: reqwest's own message leaves them out ("error
/// sending request for url" doesn't say that the connection closed under the request).
struct Causes<'a>(&'a dyn std::error::Error);

impl fmt::Display for Causes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(cause) = source {
            write!(f, ": {cause}")?;
            source = cause.source();
        }
        Ok(())
    }
}

/// Download and decrypt a sticker manifest
async fn download_sticker_pack<C: ContentsStore>(
    mut store: C,
    mut unidentified_websocket: SignalWebSocket<websocket::Unidentified>,
    operation: &StickerPackOperation,
) -> Result<StickerPack, Error<C::ContentsStoreError>> {
    debug!("downloading sticker pack");
    let pack_key = operation.pack_key();
    let pack_id = operation.pack_id();
    let key = derive_key(pack_key)?;

    let mut ciphertext = Vec::new();

    let size_bytes = unidentified_websocket
        .get_sticker_pack_manifest(&hex::encode(pack_id))
        .await?
        .read_to_end(&mut ciphertext)
        .await?;

    trace!(size_bytes, "downloaded encrypted sticker pack manifest");

    decrypt_in_place(key, &mut ciphertext)?;

    let mut sticker_pack_manifest: StickerPackManifest =
        libsignal_service::proto::Pack::decode(ciphertext.as_slice())
            .map_err(ProvisioningError::from)?
            .into();

    for sticker in &mut sticker_pack_manifest.stickers {
        match download_sticker::<C>(&mut unidentified_websocket, pack_id, pack_key, sticker.id)
            .await
        {
            Ok(decrypted_sticker_bytes) => {
                debug!(id = sticker.id, "downloaded sticker");
                sticker.bytes = Some(decrypted_sticker_bytes);
            }
            Err(error) => error!(sticker.id, %error,"failed to download sticker"),
        }
    }

    let sticker_pack = StickerPack {
        id: pack_id.to_vec(),
        key: pack_key.to_vec(),
        manifest: sticker_pack_manifest,
    };

    // save everything in store
    store.add_sticker_pack(&sticker_pack).await?;

    Ok(sticker_pack)
}

/// Downloads and decrypts a single sticker
async fn download_sticker<C: ContentsStore>(
    unidentified_websocket: &mut SignalWebSocket<websocket::Unidentified>,
    pack_id: &[u8],
    pack_key: &[u8],
    sticker_id: u32,
) -> Result<Vec<u8>, Error<C::ContentsStoreError>> {
    let key = derive_key(pack_key)?;

    let mut sticker_stream = unidentified_websocket
        .get_sticker(&hex::encode(pack_id), sticker_id)
        .await?;

    let mut ciphertext = Vec::new();
    let size_bytes = sticker_stream.read_to_end(&mut ciphertext).await?;

    trace!(size_bytes, "downloaded encrypted sticker");

    decrypt_in_place(key, &mut ciphertext)?;

    Ok(ciphertext)
}

/// Save a message into the store.
/// Note that `override_thread` can be used to specify the thread the message will be stored in.
/// This is required when storing outgoing messages, as in this case the appropriate storage place cannot be derived from the message itself.
async fn save_message<S: Store>(
    store: &mut S,
    identified_websocket: &mut websocket::SignalWebSocket<websocket::Identified>,
    message: Content,
    override_thread: Option<Thread>,
) -> Result<(), Error<S::Error>> {
    // derive the thread from the message type
    let thread = override_thread.unwrap_or(Thread::try_from(&message)?);

    // only save DataMessage and SynchronizeMessage (sent)
    let message = match message.body {
        ContentBody::DecryptionErrorMessage(e) => {
            warn!(error = ?e, "was asked to save a DecryptionErrorMessage; this should not happen");
            None
        }
        ContentBody::NullMessage(_) => Some(message),
        ContentBody::DataMessage(
            ref data_message @ DataMessage {
                ref profile_key, ..
            },
        )
        | ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    message:
                        Some(
                            ref data_message @ DataMessage {
                                ref profile_key, ..
                            },
                        ),
                    ..
                })),
            ..
        }) => {
            // update recipient profile key if changed
            if let Some(profile_key_bytes) = profile_key.clone().and_then(|p| p.try_into().ok()) {
                let sender = message.metadata.sender;
                let profile_key = ProfileKey::create(profile_key_bytes);
                let changed = store
                    .profile_key(&sender)
                    .await?
                    .is_none_or(|known| known.bytes != profile_key.bytes);

                // The key now, before the message is handed on: sending to them by sealed
                // sender needs it, and a task in the background may not get to finish.
                if let (true, Some(aci)) = (changed, sender.aci()) {
                    debug!(sender = %sender.service_id_string(), "inserting profile key for");
                    store.upsert_profile_key(&aci.into(), profile_key).await?;
                }

                // Either:
                // - insert a new contact with the profile information
                // - update the contact if the profile key has changed
                // TODO: mark this contact as "created by us" maybe to know whether we should update it or not
                // NOTE: fetching the profile needs to happen in the background!
                if changed || store.contact_by_id(&sender).await?.is_none() {
                    let store_inner = store.clone();
                    let websocket_inner = identified_websocket.clone();
                    let data_message_inner = data_message.clone();
                    tokio::spawn(async move {
                        if let Err(error) = upsert_contact_from_profile(
                            store_inner,
                            websocket_inner,
                            &data_message_inner,
                            sender,
                            profile_key,
                        )
                        .await
                        {
                            error!(%error, "failed to upsert newly seen contact!");
                        }
                    });
                }
            }

            // Note: The expire timer fields of data messages are only for contacts.
            // Expire timers are handled for groups via upsert_group due to a revision change.
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

            match data_message {
                DataMessage {
                    delete:
                        Some(Delete {
                            target_sent_timestamp: Some(ts),
                        }),
                    ..
                } => {
                    let sent = message.metadata.client_timestamp.timestamp_millis() as u64;
                    match store.message_sent_or_edited_at(&thread, *ts).await? {
                        // replace an existing message by an empty NullMessage
                        Some(mut existing_msg)
                            if existing_msg.metadata.sender == message.metadata.sender
                                && sent.saturating_sub(*ts) < DELETE_FOR_EVERYONE_WINDOW_MS =>
                        {
                            existing_msg.metadata.sender = Aci::from(Uuid::nil()).into();
                            existing_msg.body = NullMessage::default().into();
                            store.save_message(&thread, existing_msg).await?;
                            debug!(%thread, ts, "message in thread deleted");
                        }
                        Some(_) => {
                            warn!(%thread, ts, "ignoring delete of a message by someone else or too old");
                        }
                        None => warn!(%thread, ts, "could not find message to delete in thread"),
                    }
                    None
                }
                _ => Some(message),
            }
        }
        ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(SyncContent::DeleteForMe(ref delete)),
            ..
        }) => {
            // TODO: Conversations, local-only deletes, attachments
            for d in delete.message_deletes.iter().flat_map(|m| &m.messages) {
                let sender = match &d.author {
                    Some(Author::AuthorServiceId(id)) => {
                        ServiceId::parse_from_service_id_string(id)
                    }
                    Some(Author::AuthorServiceIdBinary(id)) => {
                        ServiceId::parse_from_service_id_binary(id)
                    }
                    Some(Author::AuthorE164(_)) => None,
                    None => None,
                };
                let Some(sender) = sender else {
                    tracing::warn!("Could not parse author of delete-for-self message; ignoring.");
                    continue;
                };
                let Some(timestamp) = d.sent_timestamp else {
                    tracing::warn!("Timestamp of delete-for-self message not given; ignoring.");
                    continue;
                };
                let Ok(Some(thread)) = store
                    .thread_for_sender_and_timestamp(&sender, timestamp)
                    .await
                else {
                    tracing::warn!(
                        "Message referenced by delete-for-self message not found; ignoring."
                    );
                    continue;
                };
                // Note: Not marking the message as deleted, like when receiving deletion requests by others.
                // This matches the behavior of Signal Desktop, where the message completely disappears from the timeline.
                let result = store.delete_message(&thread, timestamp).await;
                if !result.is_ok_and(|d| d) {
                    tracing::warn!(
                        "Could not delete message referenced by delete-for-self message; ignoring."
                    );
                }
            }
            None
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
        }) => match store.message_sent_or_edited_at(&thread, target).await? {
            // An edit takes the place of the message it edits, which must be its sender's, and
            // names it by its first time, also when it came naming an earlier edit's.
            Some(original) if original.metadata.sender == message.metadata.sender => {
                let mut edit = message;
                edit.metadata.client_timestamp = original.metadata.client_timestamp;
                retarget_edit(&mut edit, original.timestamp());
                Some(edit)
            }
            _ => {
                warn!(%thread, target, "ignoring edit of a message by someone else or not found");
                None
            }
        },
        // Call signaling is transient; calls are recorded by `CallEvent`s instead.
        ContentBody::CallMessage(_) => None,
        ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(SyncContent::CallEvent(_)),
            ..
        }) => Some(message),
        ContentBody::SynchronizeMessage(msg) => {
            debug!(
                ?msg,
                "skipping saving sync message without interesting fields"
            );
            None
        }
        ContentBody::ReceiptMessage(_) => Some(message),
        ContentBody::TypingMessage(msg) => {
            debug!(?msg, "skipping saving typing message");
            None
        }
        ContentBody::StoryMessage(msg) => {
            debug!(?msg, "skipping story message");
            None
        }
        ContentBody::EditMessage(msg) => {
            debug!(?msg, "invalid edited");
            None
        }
    };

    if let Some(message) = message {
        // Messages are stored by thread and time, so a sender's message must not take the
        // place of someone else's. A receipt gives way: one that went out or came in at the
        // millisecond of a message must not keep that message out, nor take its place.
        let ts = message.metadata.client_timestamp.timestamp_millis() as u64;
        let receipt = |content: &Content| matches!(content.body, ContentBody::ReceiptMessage(_));
        match store.message(&thread, ts).await? {
            Some(existing) if receipt(&message) && !receipt(&existing) => {
                debug!(%thread, ts, "not saving a receipt in the place of a message");
            }
            Some(existing)
                if existing.metadata.sender != message.metadata.sender && !receipt(&existing) =>
            {
                warn!(%thread, ts, "not saving a message in the place of someone else's");
            }
            _ => store.save_message(&thread, message).await?,
        }
    }

    Ok(())
}

/// Points an edit at `original`, the first time of the message it edits.
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

/// How long after sending a message its sender can still delete it for everyone, as received.
/// See Signal-Android's [RemoteDeleteUtil](https://github.com/signalapp/Signal-Android/blob/main/app/src/main/java/org/thoughtcrime/securesms/util/RemoteDeleteUtil.kt).
const DELETE_FOR_EVERYONE_WINDOW_MS: u64 = 2 * 24 * 60 * 60 * 1000;

async fn upsert_contact_from_profile<S: Store>(
    mut store: S,
    mut identified_websocket: SignalWebSocket<websocket::Identified>,
    data_message: &DataMessage,
    sender: ServiceId,
    profile_key: ProfileKey,
) -> Result<(), Error<<S as Store>::Error>> {
    if let Some(aci) = sender.aci() {
        let sender_uuid: Uuid = aci.into();
        let encrypted_profile = identified_websocket
            .retrieve_profile_by_id(aci, Some(profile_key))
            .await?;
        let profile_cipher = ProfileCipher::new(profile_key);
        let decrypted_profile = profile_cipher.decrypt(encrypted_profile)?;

        let contact = Contact {
            uuid: sender_uuid,
            phone_number: None,
            name: decrypted_profile
                .name
                // FIXME: this assumes [firstname] [lastname]
                .map(|pn| {
                    if let Some(family_name) = pn.family_name {
                        format!("{} {}", pn.given_name, family_name)
                    } else {
                        pn.given_name
                    }
                })
                .unwrap_or_default(),
            profile_key: profile_key.bytes.to_vec(),
            expire_timer: data_message.expire_timer.unwrap_or_default(),
            expire_timer_version: data_message.expire_timer_version.unwrap_or(1),
            inbox_position: 0,
            avatar: None,
            verified: Verified::default(),
        };

        info!(%sender_uuid, "saved contact on first sight");
        store.save_contact(&contact).await?;
    } else {
        debug!("not storing profile for PNI contact");
    }
    Ok(())
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

/// Sealed sender for a story to someone whose profile key isn't known: the server stores a story
/// without its sender, so it must be sealed, and it checks no access key for one
/// (Signal-Server `MessageController`), so any key will do.
fn story_access(
    content_body: &ContentBody,
    sender_certificate: &SenderCertificate,
) -> Option<UnidentifiedAccess> {
    matches!(content_body, ContentBody::StoryMessage(_)).then(|| UnidentifiedAccess {
        key: vec![0; 16],
        certificate: sender_certificate.clone(),
    })
}

#[cfg(test)]
mod transfer_archive_tests {
    use super::{TransferArchive, TransferArchiveResponse};

    fn parse(json: &str) -> TransferArchive {
        serde_json::from_str::<TransferArchiveResponse>(json)
            .unwrap()
            .into()
    }

    #[test]
    fn parses_all_server_responses() {
        assert_eq!(
            parse(r#"{"cdn":3,"key":"abc-_123"}"#),
            TransferArchive::Uploaded {
                cdn: 3,
                key: "abc-_123".into()
            }
        );
        assert_eq!(
            parse(r#"{"error":"RELINK_REQUESTED"}"#),
            TransferArchive::RelinkRequested
        );
        assert_eq!(
            parse(r#"{"error":"CONTINUE_WITHOUT_UPLOAD"}"#),
            TransferArchive::ContinueWithoutUpload
        );
    }
}

#[cfg(test)]
mod invitation_tests {
    use super::*;
    use crate::model::{
        groups::{Group, PendingMember},
        ServiceIdType,
    };

    fn pending(uuid: Uuid, service_id_type: ServiceIdType) -> PendingMember {
        PendingMember {
            uuid,
            service_id_type,
            role: libsignal_service::groups_v2::Role::Default,
            added_by_aci: Aci::from(Uuid::from_u128(9)),
            timestamp: 0,
        }
    }

    #[test]
    fn a_change_is_told_to_members_and_invitees_but_not_us() {
        let aci = Aci::from(Uuid::from_u128(1));
        let pni = libsignal_service::protocol::Pni::from(Uuid::from_u128(2));
        let member = |n| crate::model::groups::Member {
            aci: Aci::from(Uuid::from_u128(n)),
            role: libsignal_service::groups_v2::Role::Default,
            profile_key: ProfileKey::create([0; 32]),
            joined_at_revision: 0,
            label: None,
            label_emoji: None,
        };
        let group = Group {
            title: String::new(),
            avatar: String::new(),
            disappearing_messages_timer: None,
            access_control: None,
            revision: 0,
            members: vec![member(1), member(3)],
            pending_members: vec![
                pending(Uuid::from_u128(2), ServiceIdType::PhoneNumberIdentity),
                pending(Uuid::from_u128(4), ServiceIdType::PhoneNumberIdentity),
                pending(Uuid::from_u128(3), ServiceIdType::AccountIdentity),
            ],
            requesting_members: vec![],
            invite_link_password: vec![],
            description: None,
        };
        assert_eq!(
            told_of_changes(&group, aci, pni),
            vec![
                ServiceId::Aci(Aci::from(Uuid::from_u128(3))),
                ServiceId::Pni(libsignal_service::protocol::Pni::from(Uuid::from_u128(4))),
            ]
        );
    }

    #[test]
    fn finds_our_invitation_by_either_identity() {
        let aci = Aci::from(Uuid::from_u128(1));
        let pni = libsignal_service::protocol::Pni::from(Uuid::from_u128(2));
        let group = |pending_members| Group {
            title: String::new(),
            avatar: String::new(),
            disappearing_messages_timer: None,
            access_control: None,
            revision: 0,
            members: vec![],
            pending_members,
            requesting_members: vec![],
            invite_link_password: vec![],
            description: None,
        };
        assert_eq!(invited_as(&group(vec![]), aci, pni), None);
        let by_aci = group(vec![pending(
            Uuid::from_u128(1),
            ServiceIdType::AccountIdentity,
        )]);
        assert_eq!(invited_as(&by_aci, aci, pni), Some(ServiceId::Aci(aci)));
        let by_pni = group(vec![pending(
            Uuid::from_u128(2),
            ServiceIdType::PhoneNumberIdentity,
        )]);
        assert_eq!(invited_as(&by_pni, aci, pni), Some(ServiceId::Pni(pni)));
        // Our ACI's UUID as someone's PNI (or the other way round) isn't us.
        let mixed = group(vec![
            pending(Uuid::from_u128(1), ServiceIdType::PhoneNumberIdentity),
            pending(Uuid::from_u128(3), ServiceIdType::AccountIdentity),
        ]);
        assert_eq!(invited_as(&mixed, aci, pni), None);
    }
}

/// Whether a group change was refused because someone else changed the group meanwhile.
fn is_conflict(error: &libsignal_service::push_service::ServiceError) -> bool {
    matches!(
        error,
        libsignal_service::push_service::ServiceError::UnhandledResponseCode { status, .. }
            if status.as_u16() == 409
    )
}

/// Who is told of a change to `group`: its members and invitees as stored, without us. Signal's
/// apps tell the same, also when we only ask to join a group we were in.
fn told_of_changes(
    group: &crate::model::groups::Group,
    aci: Aci,
    pni: libsignal_service::protocol::Pni,
) -> Vec<ServiceId> {
    use crate::model::ServiceIdType;
    let mut told: Vec<ServiceId> = group.members.iter().map(|m| m.aci.into()).collect();
    told.extend(
        group
            .pending_members
            .iter()
            .map(|m| match m.service_id_type {
                ServiceIdType::AccountIdentity => ServiceId::Aci(m.uuid.into()),
                ServiceIdType::PhoneNumberIdentity => ServiceId::Pni(m.uuid.into()),
            }),
    );
    told.retain(|m| *m != ServiceId::Aci(aci) && *m != ServiceId::Pni(pni));
    told.sort();
    told.dedup();
    told
}

/// Which of our identities `group` has an invitation for.
fn invited_as(
    group: &crate::model::groups::Group,
    aci: Aci,
    pni: libsignal_service::protocol::Pni,
) -> Option<ServiceId> {
    use crate::model::ServiceIdType;
    group
        .pending_members
        .iter()
        .find_map(|m| match m.service_id_type {
            ServiceIdType::AccountIdentity if m.uuid == Uuid::from(aci) => {
                Some(ServiceId::Aci(aci))
            }
            ServiceIdType::PhoneNumberIdentity if m.uuid == Uuid::from(pni) => {
                Some(ServiceId::Pni(pni))
            }
            _ => None,
        })
}

/// See [`Manager::change_group`].
#[derive(Debug, Clone)]
pub enum GroupEdit {
    Title(String),
    /// Empty clears it.
    Description(String),
    /// The picture's bytes (JPEG or PNG, as Signal's clients send); empty clears it.
    Avatar(Vec<u8>),
    /// Seconds; 0 turns disappearing messages off.
    Timer(u32),
    /// Adds members we have a profile key for; invites the others, including PNIs.
    AddMembers(Vec<ServiceId>),
    RemoveMember(Aci),
    /// Makes a member an administrator, or takes that back.
    SetAdmin(Aci, bool),
    Leave,
    /// Joins a group we were invited to, by ACI or PNI.
    AcceptInvitation,
    /// Turns an invitation down.
    DeclineInvitation,
    /// Who the invite link lets in: `Unsatisfiable` turns it off, `Any` lets anyone join,
    /// `Administrator` makes them ask. Turning it on makes a password if there is none.
    InviteLinkAccess(AccessRequired),
    /// A new password: the links given out so far stop working.
    ResetInviteLink,
    /// Lets someone in who asked to join.
    ApproveRequest(Aci),
    /// Turns their request down.
    DenyRequest(Aci),
}

/// Fetches the group and stores it, refreshing the cached avatar if `avatar_path` (the stored
/// one) is no longer the group's.
async fn fetch_group<S: Store>(
    store: &S,
    groups_manager: &mut GroupsManager<GroupCredentialsCache>,
    master_key: [u8; 32],
    avatar_path: Option<String>,
) -> Result<(), Error<S::Error>> {
    let encrypted_group = groups_manager
        .fetch_encrypted_group(&mut rand::rng(), &master_key)
        .await?;
    let group = decrypt_group(&master_key, encrypted_group)?;
    // A new picture, or none any more: the cached one is stale.
    if avatar_path.is_some_and(|path| path != group.avatar) {
        let avatar = if group.avatar.is_empty() {
            Some(Vec::new())
        } else {
            groups_manager
                .retrieve_avatar(
                    &group.avatar,
                    GroupSecretParams::derive_from_master_key(GroupMasterKey::new(master_key)),
                )
                .await
                .unwrap_or_default()
        };
        if let Some(avatar) = avatar {
            if let Err(error) = store.save_group_avatar(master_key, &avatar).await {
                warn!(%error, "failed to save the group avatar");
            }
        }
    }
    if let Err(error) = store.save_group(master_key, group).await {
        error!(%error, "failed to save group");
    }
    Ok(())
}

/// How [`Manager::join_group`] went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupJoin {
    /// We are in; the members were told at this timestamp.
    Joined { timestamp: u64 },
    /// An administrator has to let us in. Meanwhile the group is stored with what the link
    /// shows of it, and us among its requesting members.
    Requested,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use libsignal_service::{
        configuration::SignalServers,
        prelude::{phonenumber::PhoneNumber, Uuid},
        proto::DataMessage,
        push_service::ServiceIds,
        zkgroup::profiles::ProfileKey,
    };

    use super::{Registered, RegistrationData};
    use crate::Manager;

    fn manager() -> Manager<(), Registered> {
        Manager {
            store: (),
            state: Registered::with_data(RegistrationData {
                signal_servers: SignalServers::Production,
                device_name: None,
                phone_number: PhoneNumber::from_str("+15555550100").unwrap(),
                service_ids: ServiceIds {
                    aci: Uuid::from_u128(1),
                    pni: Uuid::from_u128(2),
                },
                password: String::new(),
                device_id: None,
                registration_id: 1,
                pni_registration_id: None,
                profile_key: ProfileKey::create([0; 32]),
                ephemeral_backup_key: None,
            }),
        }
    }

    fn message(body: &str) -> DataMessage {
        DataMessage {
            body: Some(body.to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn a_message_gets_a_link_preview_by_default() {
        let manager = manager();
        let message = message("https://example.org");
        assert_eq!(
            manager.state.automatic_link_preview_body(&message),
            Some("https://example.org")
        );
    }

    #[test]
    fn a_message_with_a_preview_gets_none() {
        let manager = manager();
        let mut message = message("https://example.org");
        message.preview.push(Default::default());
        assert_eq!(manager.state.automatic_link_preview_body(&message), None);
    }

    #[test]
    fn automatic_link_previews_turned_off_fetch_nothing_in_any_clone() {
        let manager = manager();
        let clone = manager.clone();
        manager.set_automatic_link_previews(false);
        let message = message("https://example.org");
        assert_eq!(manager.state.automatic_link_preview_body(&message), None);
        assert_eq!(clone.state.automatic_link_preview_body(&message), None);
    }
}

#[cfg(test)]
mod causes_tests {
    use super::Causes;

    /// A broken connection is worth fetching again; a refusal isn't.
    #[test]
    fn only_a_failed_connection_is_fetched_again() {
        use super::{transient, ServiceError};
        assert!(transient(&ServiceError::Timeout { attempts: 1 }));
        assert!(transient(&ServiceError::IO(std::io::Error::other("reset"))));
        assert!(!transient(&ServiceError::Unauthorized));
    }

    /// The causes follow the error, as reqwest's own message leaves them out.
    #[test]
    fn an_error_is_logged_with_its_causes() {
        #[derive(Debug, thiserror::Error)]
        #[error("error sending request for url")]
        struct Sending(#[source] std::io::Error);

        let error = Sending(std::io::Error::other(
            "connection closed before message completed",
        ));
        assert_eq!(
            Causes(&error).to_string(),
            "error sending request for url: connection closed before message completed"
        );
        assert_eq!(Causes(&std::io::Error::other("alone")).to_string(), "alone");
    }
}
