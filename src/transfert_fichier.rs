use log::{debug, error, info, warn};
use std::error::Error;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_util::io::StreamReader;

use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::IsConfigNoeud;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::{futures_util, reqwest};
use millegrilles_common_rust::futures::Stream;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use millegrilles_common_rust::futures::stream::TryStreamExt;
use millegrilles_common_rust::futures_util::{StreamExt, TryStream};
use millegrilles_common_rust::futures_util::io::BufWriter;
use millegrilles_common_rust::futures_util::sink::Buffer;
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
const MESSAGE_SIZE_LIMIT: usize = 200 * 1024;

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
        let response_local = connecter_local(middleware, gestionnaire, fuuid).await?;
        debug!("Reponse local : {:?}", response_local);
        let taille_fichier = match response_local.headers().get("content-length") {
            Some(cl) => {
                debug!("Content-Length : {:?}", cl);
                match cl.to_str() {
                    Ok(len) => {
                        match len.parse::<usize>() {
                            Ok(len_usize) => Some(len_usize),
                            Err(e) => None
                        }
                    },
                    Err(_e) => None,
                }
            },
            None => None
        };
        debug!("Traitement fichier taille : {:?}", taille_fichier);
        let mut handler = UploadHandler { taille: taille_fichier };
        let reponse = handler.upload(gestionnaire, response_local, fuuid, url).await?;

        // let reponse: Response = if multiple {
        //     todo!("Fix me")
        // } else {
        //     // Transfert simple et direct. Ouvrir writer aupres de la millegrille distante
        //     let body_stream = reqwest::Body::wrap_stream(reponse_local.bytes_stream());
        //     connecter_remote(gestionnaire, url, fuuid, body_stream).await?
        // };

        debug!("Reponse client put : {:?}", reponse);

        let status_code = reponse.status().as_u16();
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

async fn connecter_remote(gestionnaire: &GestionnairePostmaster, url: &str, fuuid: &str, position: Option<usize>, stream: Body)
    -> Result<Response, Box<dyn Error>>
{
    let client = gestionnaire.http_client_remote.as_ref().expect("client reqwest fichiers remote");

    let mut url_put_fichier = Url::parse(url)?;
    let url_liste_fichiers_str = match position {
        Some(p) => format!("{}/poster/{}/{}", url_put_fichier.path(), fuuid, p),
        None => format!("{}/poster/{}", url_put_fichier.path(), fuuid),
    };
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

struct UploadHandler {
    taille: Option<usize>,
}

impl UploadHandler {
    async fn upload(&self, gestionnaire: &GestionnairePostmaster, response_local: Response, fuuid: &str, url: &str) -> Result<Response, Box<dyn Error>> {
        let split = match self.taille { Some(t) => t >= MESSAGE_SIZE_LIMIT, None => true };

        match split {
            true => self.upload_split(gestionnaire, response_local, fuuid, url).await,
            false => self.upload_simple(gestionnaire, response_local, fuuid, url).await
        }
    }

    async fn upload_simple(&self, gestionnaire: &GestionnairePostmaster, response_local: Response, fuuid: &str, url: &str) -> Result<Response, Box<dyn Error>> {
        let body_stream = reqwest::Body::wrap_stream(response_local.bytes_stream());
        let reponse = connecter_remote(gestionnaire, url, fuuid, None, body_stream).await?;
        Ok(reponse)
    }

    async fn upload_split(&self, gestionnaire: &GestionnairePostmaster, response_local: Response, fuuid: &str, url: &str) -> Result<Response, Box<dyn Error>> {
        let byte_stream = response_local.bytes_stream();
        let mut reader = StreamReader::new(byte_stream.map_err(convert_err));

        let mut buf = [0; 32768];
        let mut buf_bytes: Vec<u8> = Vec::new();
        buf_bytes.reserve(MESSAGE_SIZE_LIMIT);
        let mut position: usize = 0;
        loop {
            let len_read = reader.read(&mut buf).await?;

            let taille_buf = buf_bytes.len();
            if taille_buf + len_read < MESSAGE_SIZE_LIMIT {
                buf_bytes.extend(&buf[..len_read]);
            } else {
                // Split
                let fin_read = MESSAGE_SIZE_LIMIT - taille_buf;
                buf_bytes.extend(&buf[..fin_read]);

                let position_courante = position;
                position += buf_bytes.len();  // Incrementer position courante

                debug!("Uploader buffer len {:?}", buf_bytes.len());
                let reponse_part = self.upload_part(gestionnaire, fuuid, url, position_courante, buf_bytes).await?;
                if ! reponse_part.status().is_success() {
                    Err(format!("transfert_fichier.upload_split Echec upload fichier split {} : http status {}", fuuid, reponse_part.status().as_u16()))?;
                }

                // Remettre reste du buffer
                buf_bytes = Vec::new();
                buf_bytes.reserve(MESSAGE_SIZE_LIMIT);
                buf_bytes.extend(&buf[fin_read..]);
            }

            // debug!("Data lu : {:?}", len_read);
            if len_read == 0 { break; }
        }

        if buf_bytes.len() > 0 {
            debug!("Emttre derniere partie du fichier len: {:?}", buf_bytes.len());
            self.upload_part(gestionnaire, fuuid, url, position, buf_bytes).await?;
        }

        upload_post_final(gestionnaire, url, fuuid).await
    }

    async fn upload_part(&self, gestionnaire: &GestionnairePostmaster, fuuid: &str, url: &str, position: usize, buffer: Vec<u8>) -> Result<Response, Box<dyn Error>> {
        let body_stream = reqwest::Body::from(buffer);
        let reponse = connecter_remote(gestionnaire, url, fuuid, Some(position), body_stream).await?;
        Ok(reponse)
    }

}

async fn upload_post_final(gestionnaire: &GestionnairePostmaster, url: &str, fuuid: &str)
    -> Result<Response, Box<dyn Error>>
{
    let client = gestionnaire.http_client_remote.as_ref().expect("client reqwest fichiers remote");

    let mut url_post_fichier = Url::parse(url)?;
    let url_liste_fichiers_str = format!("{}/poster/{}", url_post_fichier.path(), fuuid);
    url_post_fichier.set_path(url_liste_fichiers_str.as_str());

    let response = client.post(url_post_fichier).send().await?;

    Ok(response)
}
