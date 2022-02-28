use std::error::Error;
use log::{debug, error, info, warn};

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::{DELEGATION_GLOBALE_PROPRIETAIRE, RolesCertificats, Securite};
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::verificateur::VerificateurMessage;
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

    let uuid_message = match message_mappe.entete {
        Some(e) => Ok(e.uuid_transaction.clone()),
        None => Err(format!("commandes.poster_message Entete manquante du message"))
    }?;

    for destination in message_poster.destinations {
        let mut confirmations = Vec::new();
        let idmg = destination.idmg;
        for destinataire in destination.destinataires {
            let conf_dest = ConfirmationTransmissionDestinataire {
                destinataire,
                code: 500,
            };
            confirmations.push(conf_dest);
        }
        let confirmation = ConfirmationTransmission {
            uuid_message: uuid_message.clone(),
            idmg,
            destinataires: confirmations,
        };

        // Transmettre commande confirmation
        let routage = RoutageMessageAction::builder("Messagerie", "confirmerTransmission")
            .exchanges(vec![Securite::L1Public])
            .build();
        middleware.transmettre_commande(routage, &confirmation, false).await?;
    }

    Ok(())
}
