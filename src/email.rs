use std::error::Error;
use log::{debug, error, warn};

use lettre::{
    transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};
use lettre::transport::smtp::client::{Tls, TlsParameters, TlsParametersBuilder};

// use mail_headers::{headers::*, header_components::Domain, headers};
// use mail_core::{Mail, default_impl::simple_context};
// use mail_smtp::{self as smtp, ConnectionConfig};

use crate::gestionnaire::GestionnairePostmaster;
use crate::messages_struct::EmailNotification;

pub async fn post_email(gestionnaire: &GestionnairePostmaster, email: EmailNotification) -> Result<(), Box<dyn Error>> {

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
        // .tls(Tls::Required(tls_parameters))
        .build();

    let from = email_from.as_str();
    let to = email.adress.as_str();
    let subject = email.title.as_str();
    let body = email.body;

    match send_email_smtp(&mailer, from, to, subject, body).await {
        Ok(r) => {
            debug!("SMTP send ok : {:?}", r);
        },
        Err(e) => {
            error!("Erreur traitement smtp : {:?}", e);
        }
    }

    Ok(())
}

async fn send_email_smtp(
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &str,
    to: &str,
    subject: &str,
    body: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let email = Message::builder()
        .from(from.parse()?)
        .to(to.parse()?)
        .subject(subject)
        .body(body.to_string())?;

    debug!("send_email_smtp  {:?}", email);

    mailer.send(email).await?;

    Ok(())
}

// async fn post_email<S>(gestionnaire: &GestionnairePostmaster, nom_domaine: S) -> Result<(), Box<dyn Error>>
//     where S: Into<String>
// {
//     // Creer contexte - monter dans le gestionnaire pour reutilisation
//     let nom_domaine = nom_domaine.into();
//     let domaine = Domain::from_unchecked(nom_domaine.clone());
//     let ctx = simple_context::new(domaine, "unique_ctx123".parse().unwrap()).unwrap();
//
//     // don't use unencrypted con for anything but testing and
//     // simplified examples
//     let (smtp, email_from) = {
//         let guard = gestionnaire.configuration_notifications.lock()?.expect("lock");
//         let email_from = match guard.email_from.as_ref() {
//             Some(inner) => inner.to_owned(),
//             None => Err(format!("Email from manquant"))?
//         };
//         let smtp = match guard.smtp.as_ref() {
//             Some(inner) => inner.clone(),
//             None => Err(format!("Aucune configuration smtp - abort"))?
//         };
//         (smtp, email_from)
//     };
//
//     let mut mail = Mail::plain_text("Some body", &ctx);
//     mail.insert_headers(headers! {
//         _From: ["bla@example.com"],
//         _To: ["blub@example.com"],
//         Subject: "Some Mail"
//     }.unwrap());
//
//     let con_config = ConnectionConfig::builder_local_unencrypted().build();
//     // let con_config = ConnectionConfig::builder_with_port(domaine.parse()?)?
//     //     .auth()
//     //     .build();
//
//     let fut = smtp::send(mail.into(), con_config, ctx);
//     fut.await?;
//
//
//     Ok(())
// }
