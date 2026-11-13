use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::TimeZone;
use libsignal_service::push_service::HIGHEST_KNOWN_CHANGE_EPOCH;
use libsignal_service::{
    content::{Content, ContentBody, Metadata},
    groups_v2::{decrypt_group, AccessRequired, GroupInviteLink, GroupJoinInfo, GroupsManager},
    prelude::{MessageSenderError, ProtobufMessage, Uuid},
    proto::{DataMessage, GroupContextV2},
    protocol::{Aci, DeviceId, ServiceId},
    push_service::ServiceError,
    unidentified_access::UnidentifiedAccess,
    zkgroup::{
        groups::{GroupMasterKey, GroupSecretParams},
        profiles::ProfileKey,
    },
};
use rand::rng;
use tracing::{debug, error, warn};

use super::{ensure_data_message_timestamp, upsert_group, MessageSender, Registered};

use crate::manager::group_credentials::GroupCredentialsCache;
use crate::model::groups::{GroupSenderKey, SharedDevice};
use crate::model::messages::MissedGroupChange;
use crate::store::{Store, Thread};
use crate::{model::groups::Group, Error, Manager};

impl<S: Store> Manager<S, Registered> {
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
            .profile_key_credential(own, self.state.profile_key(), &server_public_params)
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
            // The change the server signed is the next revision: no need to fetch the group.
            let signed = signed.encode_to_vec();
            update_group(
                &self.store,
                &mut groups_manager,
                master_key,
                revision,
                Some(&signed),
            )
            .await?;
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
                    .profile_key_credential(own, self.state.profile_key(), &server_public_params)
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
            .profile_key_credential(own, self.state.profile_key(), &server_public_params)
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
                    profile_key: self.state.profile_key(),
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

    /// Brings the stored group up to date from the server's log of its changes, as Signal's
    /// apps do when its chat opens: what changed since the stored revision, if anything (a
    /// request to join, say, which nobody tells the admins of). Returns those changes, oldest
    /// first; fetches the group whole if none is stored or the log can't be read.
    pub async fn update_group(
        &mut self,
        master_key: &[u8; 32],
    ) -> Result<Vec<MissedGroupChange>, Error<S::Error>> {
        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        update_group(&self.store, &mut groups_manager, master_key, u32::MAX, None).await
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

    /// [`Self::send_message_to_group`]'s sends with our sender key, as Signal's apps send to a
    /// group: the key to whichever of the members' devices lack it, then the message, encrypted
    /// once, in one request. None if it can't go so (a member without an access key, fewer than
    /// two members, a refusal): then it goes to each member in turn.
    ///
    /// The key is made anew when someone it was shared with is no longer a member, and after
    /// [`SENDER_KEY_MAX_AGE`].
    pub(super) async fn send_with_sender_key(
        &mut self,
        sender: &mut MessageSender<S::AciStore>,
        master_key: [u8; 32],
        recipients: &[(ServiceId, Option<UnidentifiedAccess>, bool)],
        content_body: &ContentBody,
        timestamp: u64,
    ) -> Option<Vec<libsignal_service::sender::SendMessageResult>> {
        use libsignal_service::zkgroup::groups::{GroupMasterKey, GroupSecretParams};
        const ATTEMPTS: usize = 3;

        let recipients: Vec<(ServiceId, UnidentifiedAccess)> = recipients
            .iter()
            .map(|(recipient, access, _)| Some((*recipient, access.clone()?)))
            .collect::<Option<_>>()?;
        if recipients.len() < 2 {
            return None;
        }
        let members: std::collections::HashSet<ServiceId> =
            recipients.iter().map(|(recipient, _)| *recipient).collect();
        let now = Self::now();
        let key = match self.current_sender_key(master_key, &members, now).await {
            Ok(key) => key,
            Err(error) => {
                warn!(%error, "no sender key for the group; to each member instead");
                return None;
            }
        };
        let distribution_id = key.distribution_id;
        let group_id = GroupSecretParams::derive_from_master_key(GroupMasterKey::new(master_key))
            .get_group_identifier();
        let distribution = match sender
            .sender_key_distribution_message(distribution_id)
            .await
        {
            Ok(distribution) => distribution,
            Err(error) => {
                warn!(%error, "no sender key distribution; to each member instead");
                return None;
            }
        };
        for _ in 0..ATTEMPTS {
            let shared = self.store.sender_key_shared(distribution_id).await.ok()?;
            for (recipient, access) in &recipients {
                let has_it = |devices: &[(DeviceId, u32)]| {
                    devices.iter().all(|(device, registration_id)| {
                        shared.contains(&SharedDevice {
                            service_id: *recipient,
                            device_id: (*device).into(),
                            registration_id: *registration_id,
                        })
                    })
                };
                let devices = sender.sender_key_devices(*recipient).await.ok()?;
                if has_it(&devices) {
                    continue;
                }
                match sender
                    .send_sender_key_distribution(
                        *recipient,
                        Some(access),
                        &distribution,
                        now,
                        content_body.urgent(),
                    )
                    .await
                {
                    Ok(_) => {}
                    // Not registered: the send says so too.
                    Err(MessageSenderError::NotFound { .. }) => continue,
                    Err(error) => {
                        warn!(%error, "failed to send our sender key; to each member instead");
                        return None;
                    }
                }
                // Its devices as the send left them: it mends what the server says changed.
                let devices: Vec<SharedDevice> = sender
                    .sender_key_devices(*recipient)
                    .await
                    .ok()?
                    .into_iter()
                    .map(|(device, registration_id)| SharedDevice {
                        service_id: *recipient,
                        device_id: device.into(),
                        registration_id,
                    })
                    .collect();
                self.store
                    .share_sender_key(distribution_id, &devices)
                    .await
                    .ok()?;
            }
            match sender
                .send_with_sender_key(
                    distribution_id,
                    &group_id,
                    &recipients,
                    content_body,
                    timestamp,
                    matches!(content_body, ContentBody::TypingMessage(_)),
                    content_body.urgent(),
                )
                .await
            {
                Ok(results) => return Some(results),
                Err(MessageSenderError::SenderKeyDevicesChanged) => {
                    debug!("a member's devices changed; sending again");
                }
                Err(error) => {
                    warn!(%error, "failed to send with our sender key; to each member instead");
                    return None;
                }
            }
        }
        None
    }

    /// Makes the group's sender key anew: the next message to the group hands it to every
    /// member's devices again. For when one of them couldn't decrypt a message sent with it (a
    /// retry receipt without a ratchet key), lacking the key.
    pub async fn renew_sender_key(&self, master_key: &[u8; 32]) -> Result<(), Error<S::Error>> {
        let key = GroupSenderKey {
            distribution_id: random_uuid(),
            created_at: Self::now(),
        };
        self.store.save_group_sender_key(*master_key, key).await?;
        Ok(())
    }

    /// The group's sender key, made anew if there is none, if it is older than
    /// [`SENDER_KEY_MAX_AGE`], or if someone it was shared with is no longer among `members`.
    async fn current_sender_key(
        &mut self,
        master_key: [u8; 32],
        members: &std::collections::HashSet<ServiceId>,
        now: u64,
    ) -> Result<GroupSenderKey, S::Error> {
        if let Some(key) = self.store.group_sender_key(master_key).await? {
            let young = now.saturating_sub(key.created_at) < SENDER_KEY_MAX_AGE;
            let shared = self.store.sender_key_shared(key.distribution_id).await?;
            let gone = shared
                .iter()
                .any(|device| !members.contains(&device.service_id));
            if young && !gone {
                return Ok(key);
            }
            debug!(young, gone, "making the group's sender key anew");
        }
        let key = GroupSenderKey {
            distribution_id: random_uuid(),
            created_at: now,
        };
        self.store.save_group_sender_key(master_key, key).await?;
        Ok(key)
    }
}

/// Brings the stored group up to `revision`, as Signal's apps do: by `change`, the change a
/// message carries, if the server signed it and it is the next revision; else by the server's
/// log of the changes since the stored revision; else, or with nothing stored, by fetching the
/// group whole. Returns the changes read from the log, oldest first.
pub(super) async fn update_group<S: Store>(
    store: &S,
    groups_manager: &mut GroupsManager<GroupCredentialsCache>,
    master_key_bytes: &[u8],
    revision: u32,
    change: Option<&[u8]>,
) -> Result<Vec<MissedGroupChange>, Error<S::Error>> {
    let master_key: [u8; 32] = master_key_bytes.try_into()?;
    let stored = match store.group(master_key).await {
        Ok(stored) => stored,
        Err(error) => {
            warn!(%error, "failed to retrieve group from local db");
            None
        }
    };
    let Some(mut group) = stored else {
        fetch_group_whole(store, groups_manager, master_key, None).await;
        return Ok(Vec::new());
    };
    debug!(group_name =% group.title, "loaded group from local db");
    if group.revision >= revision {
        return Ok(Vec::new());
    }
    let avatar = group.avatar.clone();
    let signed = change.and_then(|change| {
        let context = GroupContextV2 {
            master_key: Some(master_key.to_vec()),
            revision: Some(revision),
            group_change: Some(change.to_vec()),
        };
        match groups_manager.decrypt_group_context(context) {
            Ok(changes) => changes,
            Err(error) => {
                debug!(%error, "a group change that isn't the server's; not applied");
                None
            }
        }
    });
    if let Some(changes) = signed {
        if changes.change_epoch <= HIGHEST_KNOWN_CHANGE_EPOCH && group.apply(&changes) {
            debug!(revision = group.revision, "applied the group's change");
            save_group(store, groups_manager, master_key, group, Some(avatar)).await;
            return Ok(Vec::new());
        }
    }
    let read = groups_manager
        .fetch_group_changes(&mut rand::rng(), &master_key, group.revision + 1, false)
        .await;
    match read {
        Ok(entries) => {
            debug!(
                changes = entries.len(),
                "read the group's changes from its log"
            );
            let latest = entries.iter().rev().find_map(|entry| entry.group.clone());
            if let Some(latest) = latest {
                save_group(
                    store,
                    groups_manager,
                    master_key,
                    latest.into(),
                    Some(avatar),
                )
                .await;
            }
            Ok(entries
                .into_iter()
                .filter_map(|entry| {
                    Some(MissedGroupChange {
                        changes: entry.change?,
                        signed: entry.signed_change?,
                    })
                })
                .collect())
        }
        Err(error) => {
            warn!(error = %Causes(&error), "failed to read the group's changes; fetching it whole");
            fetch_group_whole(store, groups_manager, master_key, Some(avatar)).await;
            Ok(Vec::new())
        }
    }
}

/// [`fetch_group`], once more if the connection failed: nothing fetches the group again until
/// its next message, and until then it stays as it was (a member who left, still listed). Not
/// if the server answered: a refusal (we aren't a member) would be the same again.
async fn fetch_group_whole<S: Store>(
    store: &S,
    groups_manager: &mut GroupsManager<GroupCredentialsCache>,
    master_key: [u8; 32],
    avatar_path: Option<String>,
) {
    debug!("fetching and saving group");
    let mut fetched = fetch_group(store, groups_manager, master_key, avatar_path.clone()).await;
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

/// A random (version 4) UUID, as Signal's apps make a distribution id.
fn random_uuid() -> Uuid {
    const VERSION: u128 = 0xf << 76;
    const VARIANT: u128 = 0x3 << 62;
    Uuid::from_u128((rand::random::<u128>() & !VERSION & !VARIANT) | (0x4 << 76) | (0x2 << 62))
}

/// How long the sender key a group's messages go with is kept. Signal-Desktop takes its age from
/// remote config (`desktop.senderKeyMaxAge`) and keeps one 90 days at most.
const SENDER_KEY_MAX_AGE: u64 = 30 * 24 * 60 * 60 * 1000;

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

/// Fetches the group and stores it, as [`save_group`] does.
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
    save_group(store, groups_manager, master_key, group.into(), avatar_path).await;
    Ok(())
}

/// Stores the group, refreshing the cached avatar if `avatar_path` (the stored one) is no
/// longer the group's.
async fn save_group<S: Store>(
    store: &S,
    groups_manager: &mut GroupsManager<GroupCredentialsCache>,
    master_key: [u8; 32],
    group: Group,
    avatar_path: Option<String>,
) {
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
mod distribution_id_tests {
    #[test]
    fn a_distribution_id_is_a_random_uuid() {
        let id = super::random_uuid();
        assert_eq!(id.get_version_num(), 4);
        // The RFC 4122 variant: 0b10 in the top bits of the eighth byte.
        assert_eq!(id.as_bytes()[8] >> 6, 0b10);
        assert_ne!(id, super::random_uuid());
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
