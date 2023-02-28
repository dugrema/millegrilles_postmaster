use std::error::Error;
use lettre::transport::smtp::Error as ErrorLettre;
use log::{debug, error, warn};

use lettre::{
    transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};
use lettre::transport::smtp::client::{Tls, TlsParameters, TlsParametersBuilder};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::serde_json::json;

use crate::constantes::*;
use crate::gestionnaire::GestionnairePostmaster;
use crate::messages_struct::EmailNotification;

pub async fn post_email<M>(middleware: &M, gestionnaire: &GestionnairePostmaster, email: EmailNotification)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{

    let (smtp, email_from) = {
        let config = {
            let guard = gestionnaire.configuration_notifications.lock().expect("lock");
            match guard.as_ref() {
                Some(inner) => inner.clone(),
                None => Err(format!("email.post_email Configuration email absente"))?
            }
        };

        let email_from = match config.email_from {
            Some(inner) => inner,
            None => Err(format!("email.post_email Email from manquant"))?
        };

        let smtp = match config.smtp {
            Some(inner) => inner,
            None => Err(format!("email.post_email Aucune configuration smtp - abort"))?
        };

        if smtp.password.is_none() {
            Err(format!("email.post_email Mot de passe smtp manquant - abort"))?
        }

        (smtp, email_from)
    };

    let smtp_credentials =
        Credentials::new(smtp.username, smtp.password.expect("password"));

    let tls_parameters = TlsParameters::builder(smtp.hostname.clone()).build()?;

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(smtp.hostname.as_str())?
        .credentials(smtp_credentials)
        .port(smtp.port)
        .build();

    let email_formatted = format_email(email_from.as_str(), email)?;

    debug!("post_email send_email_smtp  {:?}", email_formatted);
    if let Err(e) = mailer.send(email_formatted).await {
        error!("post_email Erreur traitement smtp : {:?}", e);
        if e.is_permanent() {
            warn!("email.post_email Erreur permanente : {:?}", e.source());
            retirer_smtp(middleware, format!("{:?}", e.source()).as_str()).await?;
        } else if e.is_transient() || e.is_timeout() {
            panic!("Creer periode d'attente emission email");
        } else {
            panic!("Erreur autre - non geree");
        }
    }

    Ok(())
}

fn format_email(from: &str, email: EmailNotification) -> Result<Message, Box<dyn Error>> {
    let email = Message::builder()
        .from(from.parse()?)
        .to(email.adress.parse()?)
        .subject(email.title.as_str())
        .body(email.body)?;
    Ok(email)
}

async fn retirer_smtp<M>(middleware: &M, reason: &str)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    let commande = json!({ "err": reason });

    let routage = RoutageMessageAction::builder(DOMAINE_MESSAGERIE, "desactiverSmtp")
        .exchanges(vec![Securite::L1Public])
        .build();

    middleware.transmettre_commande(routage, &commande, false).await?;

    panic!("Erreur permanente - Desactiver notifications email");

    Ok(())
}