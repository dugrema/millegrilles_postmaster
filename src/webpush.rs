use std::error::Error;
use log::{debug, error};

use web_push::{WebPushClient, WebPushError, WebPushMessage};

use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::IsConfigNoeud;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::constantes::*;
use crate::gestionnaire::GestionnairePostmaster;
use crate::messages_struct::PostmasterWebPushMessage;

pub async fn post_webpush<M>(
    middleware: &M, gestionnaire: &GestionnairePostmaster, user_id: &str,
    webpush_client: &WebPushClient, webpush_message: PostmasterWebPushMessage
)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509 + IsConfigNoeud
{
    let endpoint = webpush_message.endpoint.clone();

    // Convertir message en format web-push
    let message: WebPushMessage = webpush_message.try_into()?;
    debug!("post_webpush Message converti : {:?}", message);

    if let Err(e) = webpush_client.send(message).await {
        error!("post_webpush Web push error : {:?}", e);
        match e {
            WebPushError::EndpointNotFound |
            WebPushError::EndpointNotValid |
            WebPushError::Unauthorized => {
                retirer_endpoint(middleware, user_id, endpoint.as_str()).await?
            },
            _ => Err(e)?
        }
    }

    Ok(())
}

async fn retirer_endpoint<M>(middleware: &M, user_id: &str, endpoint: &str)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    let commande = json!({
        "user_id": user_id,
        "endpoint": endpoint,
    });

    let routage = RoutageMessageAction::builder(DOMAINE_MESSAGERIE, "retirerSubscriptionWebpush")
        .exchanges(vec![Securite::L1Public])
        .build();

    middleware.transmettre_commande(routage, &commande, false).await?;

    Ok(())
}
