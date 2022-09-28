use log::{debug, error, info, warn};
use std::error::Error;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};

use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::IsConfigNoeud;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::{futures_util, reqwest};
use millegrilles_common_rust::constantes::Securite::{L1Public, L2Prive};
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

use millegrilles_common_rust::tokio_util::io::StreamReader;
// for map_err
use millegrilles_common_rust::tokio::io::{AsyncReadExt};
use millegrilles_common_rust::futures;
use millegrilles_common_rust::bytes;

use crate::constantes::*;
use crate::gestionnaire::{GestionnairePostmaster, new_client_local};
use crate::messages_struct::*;

const BUFFER_SIZE: u32 = 32*1024;
const MESSAGE_SIZE_LIMIT: usize = 1 * 1024 * 1024;

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
    let resultat = match transferer_fichier(middleware, gestionnaire, fiche, fuuid, uuid_message).await {
        Ok(status_code) => {
            debug!("uploader_attachment Complete, status {}", status_code);
            // Emettre evenement de confirmation d'upload complete
            let commande = EvenementUploadAttachment::complete(uuid_message.into(), idmg.into(), fuuid.into(), status_code);
            Ok(commande)
        },
        Err(e) => {
            error!("uploader_attachment Erreur transferer fichier : {:?}", e);
            // Emettre evenement d'erreur d'upload de fichier (incomplet, retry plus tard)
            Err(EvenementUploadAttachment::erreur(uuid_message.into(), idmg.into(), fuuid.into(), 500))
        }
    };

    // Traiter evenement extrait (note : Box dyn n'est pas send, on ne peut pas faire await dans le match precedent)
    match resultat {
        Ok(c) => transmettre_confirmation_upload(middleware, c).await?,
        Err(e) => emettre_evenement_upload(middleware, e).await?
    }

    Ok(())
}

async fn emettre_evenement_upload<M>(middleware: &M, evenement: EvenementUploadAttachment)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPLOAD_ATTACHMENT)
        .exchanges(vec![L1Public])
        .build();
    middleware.emettre_evenement(routage, &evenement).await?;
    Ok(())
}

async fn transmettre_confirmation_upload<M>(middleware: &M, evenement: EvenementUploadAttachment)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    let routage = RoutageMessageAction::builder(DOMAINE_MESSAGERIE, COMMANDE_UPLOAD_ATTACHMENT)
        .exchanges(vec![L1Public])
        .build();
    middleware.transmettre_commande(routage, &evenement, false).await?;
    Ok(())
}

async fn transferer_fichier<M>(middleware: &M, gestionnaire: &GestionnairePostmaster, fiche: &FicheMillegrilleApplication, fuuid: &str, uuid_message: &str)
    -> Result<u16, Box<dyn Error>>
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
        let status_code = handler.upload(gestionnaire, response_local, fuuid, url).await?;

        return Ok(status_code)
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
            let url_liste_fichiers_str = format!("/fichiers_transfert/{}", fuuid);
            url_get_fichier.set_path(url_liste_fichiers_str.as_str());
            url_get_fichier
        },
        None => Err(format!("transfert_fichier.transferer_fichier URL fichiers n'est pas disponible"))?
    };

    debug!("connecter_local Creer pipe vers {:?}", url_get_fichier.as_str());
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
    async fn upload(&self, gestionnaire: &GestionnairePostmaster, response_local: Response, fuuid: &str, url: &str) -> Result<u16, Box<dyn Error>> {
        let split = match self.taille { Some(t) => t >= MESSAGE_SIZE_LIMIT, None => true };

        match split {
            true => self.upload_split(gestionnaire, response_local, fuuid, url).await,
            false => self.upload_simple(gestionnaire, response_local, fuuid, url).await
        }
    }

    async fn upload_simple(&self, gestionnaire: &GestionnairePostmaster, response_local: Response, fuuid: &str, url: &str) -> Result<u16, Box<dyn Error>> {
        let body_stream = reqwest::Body::wrap_stream(response_local.bytes_stream());
        let reponse = connecter_remote(gestionnaire, url, fuuid, None, body_stream).await?;
        if ! reponse.status().is_success() {
            Err(format!("Erreur upload code {}", reponse.status().as_u16()))?
        }
        Ok(reponse.status().as_u16())
    }

    async fn upload_split(&self, gestionnaire: &GestionnairePostmaster, response_local: Response, fuuid: &str, url: &str) -> Result<u16, Box<dyn Error>> {
        let byte_stream = response_local.bytes_stream();
        let mut reader = StreamReader::new(byte_stream.map_err(convert_err));

        let mut buf = [0; 32768];
        let mut buf_bytes: Vec<u8> = Vec::new();
        buf_bytes.reserve(MESSAGE_SIZE_LIMIT);
        let mut position: usize = 0;
        loop {
            let len_read = reader.read(&mut buf).await?;

            // debug!("Data lu : {:?}", len_read);
            if len_read == 0 { break; }

            let taille_buf = buf_bytes.len();
            if taille_buf + len_read < MESSAGE_SIZE_LIMIT {
                buf_bytes.extend(&buf[..len_read]);
            } else {
                // Split
                let excedent = taille_buf + len_read - MESSAGE_SIZE_LIMIT;
                let fin_read = len_read - excedent;
                debug!("Position {}, taille_buf {}, len_read {}, excedent {}, fin_read {}", position, taille_buf, len_read, excedent, fin_read);
                buf_bytes.extend(&buf[..fin_read]);

                let position_courante = position;
                position += buf_bytes.len();  // Incrementer position courante

                debug!("Uploader buffer len {:?}", buf_bytes.len());
                let reponse_part = self.upload_part(gestionnaire, fuuid, url, position_courante, buf_bytes).await?;
                let status_code = reponse_part.status().as_u16();
                if status_code == 200 {
                    match reponse_part.json::<ResponsePutFichierPartiel>().await {
                        Ok(r) => {
                            if r.ok {
                                if let Some(code) = r.code {
                                    if code == 7 {
                                        // Le fichier existe deja, on retourne la reponse. OK.
                                        return Ok(200)
                                    }
                                }
                            }
                        },
                        Err(e) => ()
                    };
                } else if ! reponse_part.status().is_success() {
                    Err(format!("transfert_fichier.upload_split Echec upload fichier split {} : http status {}", fuuid, reponse_part.status().as_u16()))?;
                }

                // Remettre reste du buffer
                buf_bytes = Vec::new();
                buf_bytes.reserve(MESSAGE_SIZE_LIMIT);
                buf_bytes.extend(&buf[fin_read..len_read]);
            }

        }

        if buf_bytes.len() > 0 {
            debug!("upload_split Emttre derniere partie du fichier len: {:?}", buf_bytes.len());
            self.upload_part(gestionnaire, fuuid, url, position, buf_bytes).await?;
        }

        let reponse_finale = upload_post_final(gestionnaire, url, fuuid).await?;
        match reponse_finale.status().is_success() {
            true => Ok(reponse_finale.status().as_u16()),
            false => Err(format!("transfert_fichier.upload_split Erreur POST upload fichier {}", reponse_finale.status().as_u16()))?
        }
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

#[cfg(test)]
mod reqwest_stream_tests {
    use std::error::Error;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use millegrilles_common_rust::configuration::{charger_configuration, ConfigMessages};
    use millegrilles_common_rust::futures::future;
    use millegrilles_common_rust::futures::stream::{FuturesUnordered, SplitSink};
    use millegrilles_common_rust::futures_util::stream::SplitStream;
    use millegrilles_common_rust::reqwest::Client;
    use millegrilles_common_rust::{tokio, tokio_stream};
    use millegrilles_common_rust::tokio_stream::StreamExt;

    use crate::test_setup::setup;
    use crate::tokio::spawn;

    use super::*;

    pub fn new_client_remote() -> Result<Client, Box<dyn Error>> {
        let client = reqwest::Client::builder()
            // .https_only(true)
            .use_rustls_tls()
            .http2_adaptive_window(true)
            .danger_accept_invalid_certs(true)  // Millegrille tierce
            .build()?;
        Ok(client)
    }

    #[tokio::test]
    async fn connecter_reqwest<'a>() {
        setup("connecter");
        debug!("Connecter");

        let config = charger_configuration().expect("config");
        let enveloppe_privee = config.get_configuration_pki().get_enveloppe_privee();

        let client_local = new_client_local(&enveloppe_privee).expect("client");

        // Get un fichier de 1MB+
        // zSEfXUALWJjpWkLE73sB1cXyi1z3LabiTqDabW8BewscyZyFRcR1ph7grrGnVfPVmt8LTTSPU8wgiNJ2vLKWrzdVPBsRDQ
        // zSEfXUETz8HgPfPvy9RkyeaJA3QASHTnEzawNyPPBS55G11GA6AhJAkPmWqk4AJdr9cqMh7g9rtBHgooSPyDEFmhbYypPf
        let url_request = Url::parse("https://mg-dev1.maple.maceroc.com:444/fichiers_transfert/zSEfXUETz8HgPfPvy9RkyeaJA3QASHTnEzawNyPPBS55G11GA6AhJAkPmWqk4AJdr9cqMh7g9rtBHgooSPyDEFmhbYypPf")
            .expect("url");
        let request = client_local.get(url_request);
        let mut reponse = request.send().await.expect("reponse");
        debug!("Reponse serveur request code : {}, headers: {:?}", reponse.status(), reponse.headers());

        let client_remote = new_client_remote().expect("client");

        let mut position = 0;
        let response_rc = Arc::new(Mutex::new(Some(reponse)));

        loop  {
            let iter = read_to_substream(response_rc.clone());
            let body = Body::wrap_stream(iter);
            let url_put = Url::parse(format!("http://mg-dev1.maple.maceroc.com:3033/fichiers/test1/{}", position).as_str())
                .expect("url");
            let reponse_put = client_remote.put(url_put)
                .header("Content-Type", "application/stream")
                .body(body)
                .send().await.expect("put");
            debug!("Reponse put : {:?}", reponse_put);
            {
                if response_rc.lock().expect("lock").is_none() {
                    debug!("Upload termine");
                    break;
                }
            }
        }

    }

    // https://stackoverflow.com/questions/58700741/is-there-any-way-to-create-a-async-stream-generator-that-yields-the-result-of-re
    fn read_to_substream(response: Arc<Mutex<Option<Response>>>) -> impl futures::TryStream<Ok = bytes::Bytes, Error = String> {
        let position = 0;

        let response_ref = response.lock().expect("lock").take().expect("take");

        futures::stream::unfold((position, response, response_ref), |state| async move {
            let (position, response, mut response_ref) = state;

            let chunk = match response_ref.chunk().await {
                Ok(c) => c,
                Err(e) => {
                    error!("read_to_substream erreur {:?}", e);
                    return None
                }
            };

            match chunk {
                Some(b) => {
                    //debug!("read_to_substream Bytes lues : {}", b.len());
                    let compteur = position + b.len();
                    if compteur < MESSAGE_SIZE_LIMIT - BUFFER_SIZE as usize {
                        Some((Ok(b), (compteur, response, response_ref)))
                    } else {
                        // Remettre reponse dans le mutex pour prochaine batch
                        debug!("read_to_substream Part complet lu : {} bytes", compteur);
                        let mut guard = response.lock().expect("lock");
                        *guard = Some(response_ref);
                        None
                    }
                },
                None => None
            }
        })

    }

    // fn read_to_substream<'a>(response: &'a mut Response) -> impl futures::Stream<Item = bytes::Bytes> + 'a {
    //     let position = 0;
    //     futures::stream::unfold((position, response), |state| async move {
    //         let (position, response) = state;
    //         let chunk = match response.chunk().await {
    //             Ok(c) => c,
    //             Err(e) => {
    //                 error!("read_to_substream erreur {:?}", e);
    //                 return None
    //             }
    //         };
    //         match chunk {
    //             Some(b) => {
    //                 debug!("read_to_substream Bytes lues : {}", b.len());
    //                 let compteur = position + b.len();
    //                 if compteur < MESSAGE_SIZE_LIMIT - BUFFER_SIZE as usize {
    //                     debug!("read_to_substream Part complet lu : {} bytes", compteur);
    //                     Some((b, (compteur, response)))
    //                 } else {
    //                     None
    //                 }
    //             },
    //             None => None
    //         }
    //     })
    //
    // }

    // async fn read_to_substream(response: &mut Response) -> Result<bool, String> {
    //     let mut complete = false;
    //     let mut compteur = 0;
    //     loop {
    //         let chunk = match response.chunk().await {
    //             Ok(c) => c,
    //             Err(e) => Err(format!("read_to_substream erreur {:?}", e))?
    //         };
    //         match chunk {
    //             Some(b) => {
    //                 debug!("read_to_substream Bytes lues : {}", b.len());
    //                 compteur += b.len();
    //                 if compteur > MESSAGE_SIZE_LIMIT - BUFFER_SIZE as usize {
    //                     debug!("read_to_substream Part complet lu : {} bytes", compteur);
    //                     return Ok(true)
    //                 }
    //             },
    //             None => return Ok(false)  // Termine
    //         }
    //     }
    // }
}

// Essai 1
        // let mut position = 0;
        // let mut complete = false;
        // let stream_reponse = reponse.bytes_stream();
        // //while ! complete {
        //     debug!("Position upload : {}", position);
        //     // let compteur_courant = Mutex::new(0);
        //     let compteur_courant_rc = Arc::new(Mutex::new(0));
        //
        //     let compteur_courant = compteur_courant_rc.clone();
        //     let take_while = stream_reponse.take(MESSAGE_SIZE_LIMIT);
        //     // let take_while = stream_reponse.take_while(move |b| {
        //     //     match b {
        //     //         Ok(result) => {
        //     //             let mut guard = compteur_courant.lock().expect("lock");
        //     //             *guard += result.len();
        //     //             *guard < MESSAGE_SIZE_LIMIT - BUFFER_SIZE as usize
        //     //         },
        //     //         Err(e) => {
        //     //             error!("connecter_reqwest Erreur stream : {:?}", e);
        //     //             false
        //     //         }
        //     //     }
        //     // });
        //     let body = reqwest::Body::wrap_stream(take_while);
        //     let url_put = Url::parse(format!("http://mg-dev1.maple.maceroc.com:3033/fichiers/test1/{}", position).as_str())
        //         .expect("url");
        //     let reponse_put = client_remote.put(url_put)
        //         .header("Content-Type", "application/stream")
        //         .body(body)
        //         .send().await.expect("put");
        //
        //     {
        //         // Ajuster position
        //         let guard = compteur_courant_rc.lock().expect("lock");
        //         position += *guard;
        //         complete = *guard == 0;  // Marqueur complete
        //     }
        //     debug!("Reponse serveur put code : {}, headers: {:?}", reponse_put.status(), reponse_put.headers());
        // //}