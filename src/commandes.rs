use std::error::Error;
use log::{debug, error, info, warn};
use core::time::Duration;
use deflate::deflate_bytes_gzip;

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::configuration::IsConfigNoeud;
use millegrilles_common_rust::constantes::{DELEGATION_GLOBALE_PROPRIETAIRE, MessageKind, RolesCertificats, Securite};
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::{CommandePostmasterPoster, ConfirmationTransmission, FicheApplication, FicheMillegrilleApplication};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::verificateur::VerificateurMessage;
use millegrilles_common_rust::reqwest;
use millegrilles_common_rust::reqwest::{Client, Url};
use web_push::{WebPushClient, WebPushError, WebPushMessage};

use crate::constantes::*;
use crate::email::post_email;
use crate::gestionnaire::GestionnairePostmaster;
use crate::messages_struct::*;
use crate::transfert_fichier::*;
use crate::webpush::post_webpush;

pub async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnairePostmaster)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509 + IsConfigNoeud
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
        COMMANDE_POUSSER_ATTACHMENT => commande_pousser_attachment(middleware, m, gestionnaire).await,
        COMMANDE_POST_NOTIFICATION => commande_post_notification(middleware, m, gestionnaire).await,

        // Commandes inconnues
        _ => Err(format!("consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}

async fn commande_poster<M>(middleware: &M, mut m: MessageValideAction, gestionnaire: &GestionnairePostmaster)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509
{
    // Extraire les attachements
    let mut attachements = match m.message.parsed.attachements.take() {
        Some(inner) => inner,
        None => Err(format!("Attachements manquants dans la commande poster"))?
    };

    let message_poster: MessageMilleGrille = match attachements.remove("message") {
        Some(inner) => serde_json::from_value(inner)?,
        None => Err(format!("Attachements manquants dans la commande poster"))?
    };
    let message_id = message_poster.id.as_str();
    debug!("commande_poster Traiter message recu : {}", message_id);

    let commande_poster: CommandePostmasterPoster = m.message.parsed.map_contenu()?;
    debug!("commande_poster Commande mappee : {:?}", commande_poster);

    // Comparer le message id de la commande et du message attache
    let message_id_commande = commande_poster.message_id.as_str();
    if message_id != message_id_commande {
        Err(format!("commandes.commande_poster Mismatch message_id de la commande et message attache"))?;
    }

    poster_message(middleware, gestionnaire, commande_poster, message_poster).await?;

    Ok(None)
}

async fn emettre_confirmation<M>(middleware: &M, commande: &CommandePostmasterPoster, code: u16)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    let idmg = commande.idmg.as_str();
    let message_id = commande.message_id.as_str();

    let confirmation = ConfirmationTransmission {
        message_id: message_id.to_owned(),
        idmg: idmg.to_owned(),
        code,
    };

    // Transmettre commande confirmation
    let routage = RoutageMessageAction::builder("Messagerie", "confirmerTransmission")
        .exchanges(vec![Securite::L1Public])
        .build();

    middleware.transmettre_commande(routage, &confirmation, false).await?;

    Ok(())
}

async fn poster_message<M>(
    middleware: &M, gestionnaire: &GestionnairePostmaster,
    commande_poster: CommandePostmasterPoster,
    message: MessageMilleGrille
)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509
{
    debug!("poster_message Commande\n{}\nMessage\n{}", serde_json::to_string(&commande_poster)?, serde_json::to_string(&message)?);

    let message_id = commande_poster.message_id.as_str();

    // Trier destinations - utiliser TOR en premier si disponible
    let destinations = trier_destinations(gestionnaire, &commande_poster.fiche);

    // Serialiser, compresser message en gzip.
    let message_bytes = serde_json::to_vec(&message)?;
    let message_bytes = deflate_bytes_gzip(&message_bytes[..]);

    let mut resultat = 0;
    for destination in destinations {
        match transmettre_message(&gestionnaire, destination, &message_bytes).await {
            Ok(inner) => {
                resultat = inner;
                break;  // Transfert complete
            },
            Err(e) => {
                warn!("poster_message Erreur transfert message {:?}", e);
                resultat = 500;
            }
        }
    }

    emettre_confirmation(middleware, &commande_poster, resultat).await?;

    Ok(())
}

async fn transmettre_message(gestionnaire: &GestionnairePostmaster, destination: &FicheApplication, message_bytes: &Vec<u8>)
    -> Result<u16, Box<dyn Error>>
{
    let mut status_reponse = None;

    debug!("transmettre_message Liste destinations triees : {:?}", destination);
    let url_app_str = format!("{}/poster", destination.url.as_str());
    let url_poster = Url::parse(url_app_str.as_str())?;

    info!("transmettre_message Poster message vers {:?}", url_poster);
    let client = match url_poster.domain() {
        Some(domaine) => {
            if domaine.ends_with(".onion") {
                match &gestionnaire.http_client_tor {
                    Some(inner) => inner,
                    None => {
                        // Tor n'est pas disponible, on skip cette adresse
                        Err(format!("commandes.transmettre_message  Tor n'est pas disponible"))?
                    }
                }
            } else {
                match &gestionnaire.http_client_remote {
                    Some(inner) => inner,
                    None => {
                        // Client https non disponible, on skip cette adresse
                        Err(format!("commandes.transmettre_message  Client https non disponible"))?
                    }
                }
            }
        },
        None => {
            warn!("transmettre_message URL sans domaine, skip");
            Err(format!("commandes.transmettre_message URL sans domaine, skip"))?
        }
    };

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("Content-Type", reqwest::header::HeaderValue::from_static("application/json"));
    headers.insert("Content-Encoding", reqwest::header::HeaderValue::from_static("gzip"));

    let request_builder = client.post(url_poster.clone())
        .headers(headers)
        .body(message_bytes.clone());

    let res = match request_builder.send().await {
        Ok(inner) => inner,
        Err(e) => {
            warn!("Erreur transmission message via {} : {:?}", url_app_str, e);
            Err(format!("Erreur transmission message via {} : {:?}", url_app_str, e))?
        }
    };

    debug!("Reponse post HTTP : {:?}", res);
    if res.status().is_success() {
        info!("poster_message SUCCES poster message vers {}, status {}", url_poster, res.status().as_u16());
        status_reponse = Some(res.status());
    } else {
        warn!("poster_message ECHEC poster message vers {}, status {}", url_poster, res.status().as_u16());
        status_reponse = Some(res.status());
    }

    // Return code reponse
    let code_reponse = match status_reponse {
        Some(r) => r.as_u16(),
        None => 503
    };

    Ok(code_reponse)
}

// async fn transmettre_message(gestionnaire: &GestionnairePostmaster, destination: &IdmgMappingDestinataires, message_bytes: Vec<u8>) -> Result<u16, Box<dyn Error>> {
//     let mut status_reponse = None;
//
//     let destinations = trier_destinations(gestionnaire, destination);
//
//     debug!("transmettre_message Liste destinations triees : {:?}", destinations);
//
//     // Boucler dans la liste des destinations pour la millegrille tierce
//     for app_config in destinations {
//         let url_app_str = format!("{}/poster", app_config.url.as_str());
//         let url_poster = match Url::parse(url_app_str.as_str()) {
//             Ok(inner) => inner,
//             Err(e) => {
//                 info!("transmettre_message Erreur parse URL {} : {:?}", url_app_str, e);
//                 continue;  // Skip
//             }
//         };
//
//         info!("transmettre_message Poster message vers {:?}", url_poster);
//         let client = match url_poster.domain() {
//             Some(domaine) => {
//                 if domaine.ends_with(".onion") {
//                     match &gestionnaire.http_client_tor {
//                         Some(inner) => inner,
//                         None => {
//                             // Tor n'est pas disponible, on skip cette adresse
//                             continue;
//                         }
//                     }
//                 } else {
//                     match &gestionnaire.http_client_remote {
//                         Some(inner) => inner,
//                         None => {
//                             // Client https non disponible, on skip cette adresse
//                             continue;
//                         }
//                     }
//                 }
//             },
//             None => {
//                 info!("transmettre_message URL sans domaine, skip");
//                 continue;
//             }
//         };
//
//         let mut headers = reqwest::header::HeaderMap::new();
//         headers.insert("Content-Type", reqwest::header::HeaderValue::from_static("application/json"));
//         headers.insert("Content-Encoding", reqwest::header::HeaderValue::from_static("gzip"));
//
//         let request_builder = client.post(url_poster.clone())
//             .headers(headers)
//             .body(message_bytes.clone());
//
//         let res = match request_builder.send().await {
//             Ok(inner) => inner,
//             Err(e) => {
//                 warn!("Erreur transmission message via {} : {:?}", url_app_str, e);
//                 continue;
//             }
//         };
//
//         debug!("Reponse post HTTP : {:?}", res);
//         if res.status().is_success() {
//             info!("poster_message SUCCES poster message vers {}, status {}", url_poster, res.status().as_u16());
//             status_reponse = Some(res.status());
//             break;  // On a reussi le transfert, pas besoin de poursuivre
//         } else {
//             warn!("poster_message ECHEC poster message vers {}, status {}", url_poster, res.status().as_u16());
//         }
//     }
//
//     // Return code reponse
//     let code_reponse = match status_reponse {
//         Some(r) => r.as_u16(),
//         None => 503
//     };
//
//     Ok(code_reponse)
// }

/// Mettre les destinations en ordre (TOR en premier si disponible)
pub fn trier_destinations<'a>(gestionnaire: &GestionnairePostmaster, destination: &'a FicheMillegrilleApplication)
    -> Vec<&'a FicheApplication>
{
    let tor_disponible = gestionnaire.http_client_tor.is_some();
    let mut destinations = Vec::new();
    for app_config in &destination.application {
        let url = match Url::parse(app_config.url.as_str()) {
            Ok(inner) => inner,
            Err(e) => {
                info!("transmettre_message Erreur parse url destination {} : {:?}", app_config.url, e);
                continue;
            }
        };
        if let Some(domaine) = url.domain() {
            if domaine.ends_with(".onion") {
                if tor_disponible {
                    // Ajouter l'adresse .onion en haut de la liste
                    destinations.insert(0, app_config);
                }
            } else {
                // Ce n'est pas une adresse TOR, ajouter a la fin de la liste
                destinations.push(app_config);
            }
        }
    }
    destinations
}

async fn commande_pousser_attachment<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnairePostmaster)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509 + IsConfigNoeud
{
    let uuid_transaction = m.message.parsed.id.as_str();
    debug!("commande_pousser_attachment Traiter message recu : {:?}", uuid_transaction);
    let message_poster: CommandePousserAttachments = m.message.parsed.map_contenu()?;
    debug!("commande_pousser_attachment Message mappe : {:?}", message_poster);

    let fiche = get_fiche(middleware, &message_poster).await?;
    let uuid_message = message_poster.uuid_message.as_str();

    // TODO Requete vers messagerie pour recuperer les fuuids a uploader
    loop {
        let prochain_attachment = get_prochain_attachment(middleware, &message_poster).await?;

        if ! prochain_attachment.ok {
            debug!("commande_pousser_attachment Reponse prochain attachement ok=false, on termine");
        }

        // Uploader l'attachment
        match prochain_attachment.fuuid.as_ref() {
            Some(f) => uploader_attachment(middleware, gestionnaire, &fiche, f.as_str(), uuid_message).await?,
            None => {
                debug!("commande_pousser_attachment Aucun fuuid recu, on termine");
                break
            }
        }
    }

    Ok(None)
}

async fn get_fiche<M>(middleware: &M, message_poster: &CommandePousserAttachments)
    -> Result<FicheMillegrilleApplication, Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509
{
    let idmg = message_poster.idmg_destination.as_str();

    let routage_topologie = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE, REQUETE_APPLICATIONS_TIERS)
        .build();
    let requete_topologie = RequeteTopologieFicheApplication { idmgs: vec![idmg.into()], application: "messagerie_web".into() };
    let reponse_topologie = middleware.transmettre_requete(routage_topologie, &requete_topologie).await?;

    debug!("get_fiche Reponse fiche topologie : {:?}", reponse_topologie);
    let reponse_topologie = match reponse_topologie {
        TypeMessage::Valide(r) => Ok(r),
        _ => Err(format!("commandes.get_fiche Reponse fiche topologie mauvais format"))
    }?;

    let reponse_mappee: ReponseFichesApplication = reponse_topologie.message.parsed.map_contenu()?;

    if reponse_mappee.fiches.len() == 1 {
        // Retourner la fiche
        if let Some(r) = reponse_mappee.fiches.into_iter().next() {
            return Ok(r)
        }
    }
    Err(format!("commandes.get_fiche Aucune fiche trouve pour l'application messagerie sur {}", idmg))?
}

async fn get_prochain_attachment<M>(middleware: &M, message_poster: &CommandePousserAttachments)
    -> Result<ReponseProchainAttachment, Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509
{
    let routage = RoutageMessageAction::builder(DOMAINE_MESSAGERIE, COMMANDE_PROCHAIN_ATTACHMENT)
        .build();

    let reponse: ReponseProchainAttachment = match middleware.transmettre_commande(routage, message_poster, true).await? {
        Some(t) => match t {
            TypeMessage::Valide(m) => Ok(m.message.parsed.map_contenu()?),
            _ => Err(format!("commandes.get_prochain_attachment Mauvais type message en reponse"))
        },
        None => Err(format!("commandes.get_prochain_attachment Aucune reponse pour le prochain attachment"))
    }?;

    debug!("get_prochain_attachment Reponse prochain attachment : {:?}", reponse);

    Ok(reponse)
}

async fn commande_post_notification<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnairePostmaster)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509 + IsConfigNoeud
{
    let message_notifications: NotificationOutgoingPostmaster = m.message.parsed.map_contenu()?;
    debug!("commande_post_notification Message mappe : {:?}", message_notifications);

    let user_id = message_notifications.user_id.clone();

    let client = WebPushClient::new()?;

    if let Some(inner) = message_notifications.webpush {
        for w in inner {
            if let Err(e) = post_webpush(middleware, gestionnaire, user_id.as_str(), &client, w).await {
                error!("commande_post_notification Erreur webpush message user_id {} : {:?}", user_id, e);
            }
        }
    }

    if let Some(inner) = message_notifications.email {
        debug!("commande_post_notification Emettre email {:?}", inner);
        if let Err(e) = post_email(middleware, gestionnaire, inner).await {
            error!("commande_post_notification Erreur post email : {:?}", e);
        }
    }

    Ok(None)
}
