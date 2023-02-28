use std::collections::HashMap;
use std::error::Error;
use log::debug;

use http::uri::Uri;

use millegrilles_common_rust::chiffrage_cle::{InformationCle, MetaInformationCle};
use millegrilles_common_rust::chrono;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::common_messages::DataChiffre;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, Entete};
use millegrilles_common_rust::multibase::decode;
use millegrilles_common_rust::openssl::conf::Conf;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{Map, Value};
use web_push::{WebPushMessage, WebPushPayload};
use crate::constantes::{CODE_UPLOAD_DEBUT, CODE_UPLOAD_ERREUR, CODE_UPLOAD_TERMINE, WEBPUSH_ENCODING_AES128, WEBPUSH_HEADER_AUTHORIZATION};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentMessage {
    pub message_chiffre: String,
    pub attachments: Option<Vec<String>>,
    pub fingerprint_certificat: String,
    pub hachage_bytes: String,

    #[serde(rename = "en-tete", skip_serializing)]
    pub entete: Option<Entete>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandePostmasterPoster {
    pub message: Map<String, Value>,
    pub destinations: Vec<IdmgMappingDestinataires>,
    pub cle_info: MetaInformationCle,
    pub certificat_message: Vec<String>,
    pub certificat_millegrille: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdmgMappingDestinataires {
    pub idmg: String,
    pub mapping: DocMappingIdmg,
    pub destinataires: Vec<String>,
    pub fiche: FicheMillegrilleApplication,
    pub cles: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocMappingIdmg {
    pub dns: Option<Vec<String>>,
    pub retry: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseFichesApplication {
    pub fiches: Vec<FicheMillegrilleApplication>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FicheMillegrilleApplication {
    pub idmg: String,
    pub adresses: Vec<String>,
    pub application: Vec<FicheApplication>,
    pub ca: Option<String>,
    pub chiffrage: Option<Vec<Vec<String>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FicheApplication {
    pub application: String,
    pub url: String,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationTransmission {
    pub uuid_message: String,
    pub idmg: String,
    pub destinataires: Vec<ConfirmationTransmissionDestinataire>,
    pub code: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationTransmissionDestinataire {
    pub destinataire: String,
    pub code: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandePousserAttachments {
    pub uuid_message: String,
    pub idmg_destination: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteTopologieFicheApplication {
    pub idmgs: Vec<String>,
    pub application: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseProchainAttachment {
    pub fuuid: Option<String>,
    pub ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvenementUploadAttachment {
    pub uuid_message: String,
    pub idmg: String,
    pub fuuid: String,
    pub code: u32,
    pub http_status: Option<u16>,
    pub retry_after: Option<u32>,
    pub complete: bool,
}

impl EvenementUploadAttachment {
    pub fn nouveau(uuid_message: String, idmg: String, fuuid: String) -> Self {
        EvenementUploadAttachment {
            uuid_message,
            idmg,
            fuuid,
            code: CODE_UPLOAD_DEBUT,
            http_status: None,
            retry_after: None,
            complete: false,
        }
    }

    pub fn complete(uuid_message: String, idmg: String, fuuid: String, http_status: u16) -> Self {
        EvenementUploadAttachment {
            uuid_message,
            idmg,
            fuuid,
            code: CODE_UPLOAD_TERMINE,
            http_status: Some(http_status),
            retry_after: None,
            complete: true,
        }
    }

    pub fn erreur(uuid_message: String, idmg: String, fuuid: String, http_status: u16) -> Self {
        EvenementUploadAttachment {
            uuid_message,
            idmg,
            fuuid,
            code: CODE_UPLOAD_ERREUR,
            http_status: Some(http_status),
            retry_after: None,
            complete: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponsePutFichierPartiel {
    pub ok: bool,
    pub code: Option<u32>,
    pub status: Option<usize>,
    pub err: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseConfigurationNotificationsWebpush {
    pub actif: Option<bool>,
    pub icon: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseConfigurationNotifictionsSmtp {
    pub actif: Option<bool>,
    pub chiffre: DataChiffre,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub replyto: Option<String>,
    pub username: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseConfigurationNotifications {
    pub email_from: Option<String>,
    pub intervalle_min: Option<i64>,
    pub webpush_public_key: Option<String>,
    pub cles: Option<HashMap<String, InformationCle>>,
    pub webpush: Option<ReponseConfigurationNotificationsWebpush>,
    pub smtp : Option<ReponseConfigurationNotifictionsSmtp>,
}

#[derive(Clone, Debug)]
pub struct ConfigurationSmtp {
    pub actif: bool,
    pub hostname: String,
    pub port: u16,
    pub replyto: Option<String>,
    pub username: String,
    pub password: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ConfigurationNotifications {
    pub email_from: Option<String>,
    pub intervalle_min: Option<i64>,
    pub smtp: Option<ConfigurationSmtp>,
    pub webpush: Option<ReponseConfigurationNotificationsWebpush>,
    pub webpush_public_key: Option<String>,
}

impl TryFrom<ReponseConfigurationNotifications> for ConfigurationNotifications {
    type Error = Box<dyn Error>;

    fn try_from(value: ReponseConfigurationNotifications) -> Result<Self, Self::Error> {
        let smtp = None;

        Ok(Self {
            email_from: value.email_from,
            intervalle_min: value.intervalle_min,
            smtp,
            webpush: value.webpush,
            webpush_public_key: value.webpush_public_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostmasterWebPushPayload {
    pub content: String,
    pub crypto_headers: HashMap<String, String>,
    pub content_encoding: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostmasterWebPushMessage {
    pub endpoint: String,
    pub ttl: u32,
    pub payload: Option<PostmasterWebPushPayload>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmailNotification {
    pub address: String,
    pub title: String,
    pub body: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationOutgoingPostmaster {
    pub user_id: String,
    pub email: Option<EmailNotification>,
    pub webpush: Option<Vec<PostmasterWebPushMessage>>,
}

impl TryInto<WebPushMessage> for PostmasterWebPushMessage {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<WebPushMessage, Self::Error> {

        let payload = match self.payload.as_ref() {
            Some(inner) => {

                // Changer encoding a 'static &str
                let content_encoding = match inner.content_encoding.as_str() {
                    WEBPUSH_ENCODING_AES128 => WEBPUSH_ENCODING_AES128,
                    _ => Err(format!("Encoding webpsuh non supporte"))?
                };

                // Mapper avec 'static str pour key
                let mut crypto_headers = Vec::new();
                for (key, value) in &inner.crypto_headers {
                    let key_str = match key.as_str() {
                        WEBPUSH_HEADER_AUTHORIZATION => WEBPUSH_HEADER_AUTHORIZATION,
                        _ => Err(format!("Header non supporte"))?
                    };
                    crypto_headers.push((key_str, value.to_owned()));
                }

                Some(WebPushPayload {
                    content: decode(&inner.content)?.1,
                    crypto_headers,
                    content_encoding,
                })
            },
            None => None
        };

        let endpoint = Uri::try_from(self.endpoint)?;

        Ok(WebPushMessage {
            endpoint,
            ttl: self.ttl,
            payload,
        })
    }
}