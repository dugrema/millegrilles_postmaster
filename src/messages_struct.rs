use std::collections::HashMap;
use log::debug;
use millegrilles_common_rust::chiffrage_cle::MetaInformationCle;

use millegrilles_common_rust::chrono;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, Entete};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{Map, Value};

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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationTransmissionDestinataire {
    pub destinataire: String,
    pub code: u32,
}