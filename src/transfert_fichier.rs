use log::{debug, error, info, warn};
use std::error::Error;
use std::io::ErrorKind;
use tokio_util::io::StreamReader;

use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::IsConfigNoeud;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::reqwest;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use millegrilles_common_rust::futures::stream::TryStreamExt;
use millegrilles_common_rust::hachages::Hacheur;
use millegrilles_common_rust::multibase::Base;
use millegrilles_common_rust::multihash::Code;
use millegrilles_common_rust::reqwest::{Body, Request, Response, Url};
// for map_err
use millegrilles_common_rust::tokio::io::{AsyncReadExt};

use crate::constantes::*;
use crate::gestionnaire::{GestionnairePostmaster, new_client_local};
use crate::messages_struct::*;

const BUFFER_SIZE: u32 = 131072;

pub async fn uploader_attachment<M>(
    middleware: &M, gestionnaire: &GestionnairePostmaster, fiche: &FicheMillegrilleApplication, fuuid: &str, uuid_message: &str)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509 + IsConfigNoeud
{
    debug!("uploader_attachment Attachment fuuid {}", fuuid);
    let idmg = fiche.idmg.as_str();

    { // Emettre evenement de debut - s'assure de confirmer que le fichier est en cours de traitement
        let evenement = EvenementUploadAttachment::nouveau(
            uuid_message.into(), idmg.into(), fuuid.into());
        emettre_evenement_upload(middleware, evenement).await?;
    }

    // Creer pipeline d'upload vers le serveur distant.
    let evenement = match transferer_fichier(middleware, gestionnaire, fiche, fuuid, uuid_message).await {
        Ok(()) => {
            // Emettre evenement de confirmation d'upload complete
            EvenementUploadAttachment::complete(uuid_message.into(), idmg.into(), fuuid.into(), 500)
        },
        Err(e) => {
            error!("uploader_attachment Erreur transferer fichier : {:?}", e);
            // Emettre evenement de confirmation d'upload complete
            EvenementUploadAttachment::erreur(uuid_message.into(), idmg.into(), fuuid.into(), 201)
        }
    };

    emettre_evenement_upload(middleware, evenement).await?;

    Ok(())
}

async fn emettre_evenement_upload<M>(middleware: &M, evenement: EvenementUploadAttachment)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPLOAD_ATTACHMENT).build();
    middleware.emettre_evenement(routage, &evenement).await?;
    Ok(())
}

async fn transferer_fichier<M>(middleware: &M, gestionnaire: &GestionnairePostmaster, fiche: &FicheMillegrilleApplication, fuuid: &str, uuid_message: &str)
    -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + IsConfigNoeud
{
    for app in &fiche.application {
        let url = app.url.as_str();

        // Ouvrir reader aupres de la millegrille locale
        let reponse_local = connecter_local(middleware, gestionnaire, fuuid).await?;

        // Ouvrir writer aupres de la millegrille distante
        let body_stream = reqwest::Body::wrap_stream(reponse_local.bytes_stream());
        let client_put = connecter_remote(gestionnaire, url, fuuid, body_stream).await?;
        debug!("Reponse client put : {:?}", client_put);

        let status_code = client_put.status().as_u16();
        if status_code >= 200 && status_code < 300 {
            return Ok(())
        } else {
            info!("Erreur PUT fichier {}, code : {}", fuuid, status_code);
        }
    }

    Err(format!("Erreur transfert fichier, aucun upload succes"))?
}

async fn connecter_local<M>(middleware: &M, gestionnaire: &GestionnairePostmaster, fuuid: &str)
    -> Result<Response, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + IsConfigNoeud
{
    let client_interne = gestionnaire.http_client_local.as_ref().expect("client reqwest fichiers locaux");

    let url_get_fichier = match &middleware.get_configuration_noeud().fichiers_url {
        Some(u) => {
            let mut url_get_fichier = u.clone();
            let url_liste_fichiers_str = format!("/fichiers/{}", fuuid);
            url_get_fichier.set_path(url_liste_fichiers_str.as_str());
            url_get_fichier
        },
        None => Err(format!("transfert_fichier.transferer_fichier URL fichiers n'est pas disponible"))?
    };

    let request_get = client_interne.get(url_get_fichier);
    let reponse = request_get.send().await?;
    debug!("transferer_fichier transferer_fichier Reponse : {:?}", reponse);
    if !reponse.status().is_success() {
        Err(format!("transfert_fichier.transferer_fichier Erreur ouverture fichier status {} : {}", reponse.status().as_u16(), reponse.url().as_str()))?
    }

    Ok(reponse)
}

async fn connecter_remote(gestionnaire: &GestionnairePostmaster, url: &str, fuuid: &str, stream: Body)
    -> Result<Response, Box<dyn Error>>
{
    let client = gestionnaire.http_client_remote.as_ref().expect("client reqwest fichiers remote");

    let mut url_put_fichier = Url::parse(url)?;
    let url_liste_fichiers_str = format!("{}/poster/{}", url_put_fichier.path(), fuuid);
    url_put_fichier.set_path(url_liste_fichiers_str.as_str());

    let response = client.put(url_put_fichier)
        .header("Content-Type", "application/stream")
        .body(stream)
        .send().await?;

    Ok(response)
}

fn convert_err(err: reqwest::Error) -> std::io::Error {
    std::io::Error::new(ErrorKind::Other, err)
}
