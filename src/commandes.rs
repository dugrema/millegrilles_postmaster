use std::error::Error;
use log::{debug, error, info, warn};

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::{DELEGATION_GLOBALE_PROPRIETAIRE, RolesCertificats, Securite};
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use crate::constantes::DOMAINE_NOM;
use crate::gestionnaire::GestionnairePostmaster;

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
        // TRANSACTION_POSTER => commande_poster(middleware, m, gestionnaire).await,

        // COMMANDE_INDEXER => commande_reindexer(middleware, m, gestionnaire).await,

        // Commandes inconnues
        _ => Err(format!("consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}
