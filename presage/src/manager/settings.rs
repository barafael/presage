use std::sync::{Arc, PoisonError, RwLock};

use libsignal_service::proto::DataMessage;

/// What a registered [`Manager`](crate::Manager) does on its own, as its user decides.
///
/// Set with [`Manager::set_settings`](crate::Manager::set_settings), shared by the manager's
/// clones. presage doesn't store them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Whether a data message sent without a preview gets one for its first link, as
    /// [`Manager::link_preview`](crate::Manager::link_preview) makes it. Fetching the page
    /// reveals the user's IP address to its server. On by default.
    pub automatic_link_previews: bool,
    /// Whether the server delivers stories to this device (`X-Signal-Receive-Stories`); without
    /// it, the server drops them unread. Applies to the connections opened after the change.
    /// Off by default.
    pub receive_stories: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            automatic_link_previews: true,
            receive_stories: false,
        }
    }
}

impl Settings {
    /// The text of `message` to fetch a link preview for, if it gets one automatically.
    pub(crate) fn automatic_link_preview_body<'a>(
        &self,
        message: &'a DataMessage,
    ) -> Option<&'a str> {
        if !self.automatic_link_previews || !message.preview.is_empty() {
            return None;
        }
        message.body.as_deref()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SharedSettings(Arc<RwLock<Settings>>);

impl SharedSettings {
    pub(crate) fn get(&self) -> Settings {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn set(&self, settings: Settings) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = settings;
    }
}

#[cfg(test)]
mod tests {
    use libsignal_service::proto::DataMessage;

    use super::{Settings, SharedSettings};

    fn message(body: &str) -> DataMessage {
        DataMessage {
            body: Some(body.to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn a_message_gets_a_link_preview_by_default() {
        let message = message("https://example.org");
        assert_eq!(
            Settings::default().automatic_link_preview_body(&message),
            Some("https://example.org")
        );
    }

    #[test]
    fn a_message_with_a_preview_gets_none() {
        let mut message = message("https://example.org");
        message.preview.push(Default::default());
        assert_eq!(
            Settings::default().automatic_link_preview_body(&message),
            None
        );
    }

    #[test]
    fn automatic_link_previews_turned_off_fetch_nothing() {
        let settings = Settings {
            automatic_link_previews: false,
            ..Default::default()
        };
        let message = message("https://example.org");
        assert_eq!(settings.automatic_link_preview_body(&message), None);
    }

    #[test]
    fn a_change_reaches_every_clone() {
        let settings = SharedSettings::default();
        let clone = settings.clone();
        settings.set(Settings {
            automatic_link_previews: false,
            ..Default::default()
        });
        assert!(!clone.get().automatic_link_previews);
    }
}
