use std::error::Error;
use log::{debug, error, info, warn};

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::{DELEGATION_GLOBALE_PROPRIETAIRE, RolesCertificats, Securite};
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use crate::gestionnaire::GestionnairePostmaster;

pub async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnairePostmaster)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + VerificateurMessage
{
    debug!("Consommer requete : {:?}", &message.message);

    let user_id = message.get_user_id();
    let role_prive = message.verifier_roles(vec![RolesCertificats::ComptePrive]);

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else if message.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege]) {
        // Autorisation : On accepte les requetes de 3.protege ou 4.secure
        // Ok
    } else if message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("consommer_requete autorisation invalide (pas d'un exchange reconnu)"))?
    }

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                // REQUETE_GET_MESSAGES => requete_get_messages(middleware, message, gestionnaire).await,
                _ => {
                    error!("Message requete/action inconnue : '{}'. Message dropped.", message.action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete/domaine inconnu : '{}'. Message dropped.", message.domaine);
            Ok(None)
        },
    }
}
