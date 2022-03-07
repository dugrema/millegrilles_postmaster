use std::error::Error;
use log::{debug, error, info, warn};
use core::time::Duration;
use deflate::deflate_bytes_gzip;

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::{DELEGATION_GLOBALE_PROPRIETAIRE, RolesCertificats, Securite};
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::verificateur::VerificateurMessage;
use millegrilles_common_rust::reqwest;

use crate::constantes::*;
use crate::gestionnaire::GestionnairePostmaster;
use crate::messages_struct::{CommandePostmasterPoster, ConfirmationTransmission, ConfirmationTransmissionDestinataire, DocumentMessage, IdmgMappingDestinataires};

pub async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnairePostmaster)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509
{
    debug!("consommer_commande : {:?}", &m.message);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else {
        match m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
            true => Ok(()),
            false => {
                // Verifier si on a un certificat delegation globale
                match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                    true => Ok(()),
                    false => Err(format!("consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id)),
                }
            }
        }?;
    }

    match m.action.as_str() {
        // Commandes standard
        COMMANDE_POSTER => commande_poster(middleware, m, gestionnaire).await,

        // Commandes inconnues
        _ => Err(format!("consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}

async fn commande_poster<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnairePostmaster)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509
{
    let uuid_transaction = m.message.parsed.entete.uuid_transaction.as_str();
    debug!("commande_poster Traiter message poster recu : {:?}", uuid_transaction);
    let message_poster: CommandePostmasterPoster = m.message.parsed.map_contenu(None)?;
    debug!("commande_poster Message mappe : {:?}", message_poster);

    poster_message(middleware, message_poster).await?;

    Ok(None)
}

async fn poster_message<M>(middleware: &M, message_poster: CommandePostmasterPoster)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509
{
    let message_mappe: DocumentMessage = {
        let value = serde_json::to_value(message_poster.message.clone())?;
        serde_json::from_value(value)?
    };

    // Ajouter _certificat et _millegrille au message
    let message_map = {
        let mut message_map = message_poster.message;
        message_map.insert("_certificat".into(), Value::from(message_poster.certificat_message.clone()));
        message_map.insert("_millegrille".into(), Value::from(message_poster.certificat_millegrille.clone()));
        message_map
    };

    let uuid_message = match message_mappe.entete {
        Some(e) => Ok(e.uuid_transaction.clone()),
        None => Err(format!("commandes.poster_message Entete manquante du message"))
    }?;

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("Content-Type", reqwest::header::HeaderValue::from_static("application/json"));
    headers.insert("Content-Encoding", reqwest::header::HeaderValue::from_static("gzip"));
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .connect_timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)  // TODO : supporter valide/invalide avec upgrade securite emission
        .build()?;

    for destination in message_poster.destinations {

        let cle_info = &message_poster.cle_info;
        let message_bytes = {
            let message_http = json!({
                "message": &message_map,
                "chiffrage": {
                    "cles": &destination.cles,
                    "domaine": "Messagerie",
                    "format": &cle_info.format,
                    "hachage_bytes": &cle_info.hachage_bytes,
                    "identificateurs_document": {
                        "message": "true"
                    },
                    "iv": &cle_info.iv,
                    "tag": &cle_info.tag,
                },
                "destinataires": &destination.destinataires,
            });
            debug!("poster_message POST message {:?}", message_http);

            // Signer le message, compresser en gzip et pousser via https
            let message_signe = middleware.formatter_message(
                &message_http, None::<&str>, None::<&str>, None::<&str>, None, true)?;
            let message_str = serde_json::to_string(&message_signe)?;

            let message_bytes = deflate_bytes_gzip(message_str.as_bytes());

            message_bytes
        };

        // Emettre message via HTTP POST
        // Boucler dans la liste des destinations pour la millegrille tierce
        let mut status_reponse = None;
        for app_config in &destination.fiche.application {
            let url_app = app_config.url.as_str();
            let url_poster = format!("{}/poster", url_app);
            debug!("Poster message vers {}", url_poster);
            let res = client.post(url_poster)
                .body(message_bytes.clone())
                .send()
                .await?;
            debug!("Reponse post HTTP : {:?}", res);
            if res.status().is_success() {
                status_reponse = Some(res.status());
                break;  // On a reussi le transfert, pas besoin de poursuivre
            }
        }

        let code_reponse = match status_reponse {
            Some(r) => r.as_u16(),
            None => 503
        };

        let mut confirmations = Vec::new();
        let idmg = destination.idmg;
        for destinataire in destination.destinataires {
            let conf_dest = ConfirmationTransmissionDestinataire {
                destinataire,
                code: code_reponse as u32,  // TODO code par usager (e.g. 404, usager non trouve)
            };
            confirmations.push(conf_dest);
        }
        let confirmation = ConfirmationTransmission {
            uuid_message: uuid_message.clone(),
            idmg,
            destinataires: confirmations,
            code: code_reponse,
        };

        // Transmettre commande confirmation
        let routage = RoutageMessageAction::builder("Messagerie", "confirmerTransmission")
            .exchanges(vec![Securite::L1Public])
            .build();
        middleware.transmettre_commande(routage, &confirmation, false).await?;
    }

    Ok(())
}
