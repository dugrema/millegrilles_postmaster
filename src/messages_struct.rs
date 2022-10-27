use std::collections::HashMap;
use log::debug;
use millegrilles_common_rust::chiffrage_cle::MetaInformationCle;

use millegrilles_common_rust::chrono;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, Entete};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{Map, Value};
use crate::constantes::{CODE_UPLOAD_DEBUT, CODE_UPLOAD_ERREUR, CODE_UPLOAD_TERMINE};

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