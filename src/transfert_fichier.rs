use log::{debug, error, info, warn};
use std::error::Error;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
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
use millegrilles_common_rust::reqwest::{Body, Client, Request, Response, Url};

use millegrilles_common_rust::tokio_util::io::StreamReader;
// for map_err
use millegrilles_common_rust::tokio::io::{AsyncReadExt};
use millegrilles_common_rust::futures;
use millegrilles_common_rust::bytes;

use crate::constantes::*;
use crate::gestionnaire::{GestionnairePostmaster, new_client_local};
use crate::messages_struct::*;

const BUFFER_SIZE: u32 = 128*1024;
const MESSAGE_SIZE_LIMIT: usize = 5 * 1024 * 1024;

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
    let destinations = trier_destinations(gestionnaire, fiche);

    debug!("transferer_fichier Destinations triees : {:?}", destinations);

    for app in destinations {
        let url = app.url.as_str();

        // Ouvrir reader aupres de la millegrille locale
        let response_local = connecter_local(middleware, gestionnaire, fuuid).await?;
        debug!("transferer_fichier Reponse local : {:?}", response_local);

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

        debug!("transferer_fichier Traitement fichier taille : {:?} vers {}", taille_fichier, url);
        let mut handler = UploadHandler { taille: taille_fichier };
        match handler.upload(gestionnaire, response_local, fuuid, url).await {
            Ok(status_code) => {
                // Complete
                debug!("transferer_fichier Reponse transfert {} : {}", url, status_code);
                return Ok(status_code)
            },
            Err(e) => {
                error!("transferer_fichier Erreur transfert vers {} : {:?}", url, e)
            }
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
    let client = get_client(gestionnaire, url)?;

    let mut url_put_fichier = Url::parse(url)?;
    let url_liste_fichiers_str = match position {
        Some(p) => format!("{}/poster/{}/{}", url_put_fichier.path(), fuuid, p),
        None => format!("{}/poster/{}", url_put_fichier.path(), fuuid),
    };
    url_put_fichier.set_path(url_liste_fichiers_str.as_str());

    let response = client.put(url_put_fichier.clone())
        .header("Content-Type", "application/stream")
        .body(stream)
        .send().await?;

    if ! response.status().is_success() {
        // Cleanup upload (aucun effet si upload simple)
        match client.delete(url_put_fichier).send().await {
            Ok(_) => (),
            Err(e) => {
                warn!("Erreur cleanup fichier sur erreur '{}' : {:?}", url_liste_fichiers_str, e);
            }
        }
    }

    Ok(response)
}

fn get_client<'a>(gestionnaire: &'a GestionnairePostmaster, url: &str) -> Result<&'a Client, Box<dyn Error>> {
    let url_parsed = Url::parse(url)?;
    let client = if let Some(domain) = url_parsed.domain() {
        if domain.ends_with(".onion") {
            // Adresse TOR
            match &gestionnaire.http_client_tor {
                Some(inner) => inner,
                None => Err(format!("Client TOR non disponible pour adresse {}", url))?
            }
        } else {
            match &gestionnaire.http_client_remote.as_ref() {
                Some(inner) => inner,
                None => Err(format!("Client HTTPS remote non disponible pour adresse {}", url))?
            }
        }
    } else {
        Err(format!("URL domaine manquant : {}", url))?
    };

    Ok(client)
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
        let stream_state_rc = Arc::new(Mutex::new(Some(StreamState {reponse: response_local, position: 0, chunk_overlap: None})));
        let iter = read_to_substream(stream_state_rc.clone());
        let body_stream = Body::wrap_stream(iter);

        let reponse = connecter_remote(gestionnaire, url, fuuid, None, body_stream).await?;

        if ! reponse.status().is_success() {
            Err(format!("Erreur upload code {}", reponse.status().as_u16()))?
        }

        Ok(reponse.status().as_u16())
    }

    async fn upload_split(&self, gestionnaire: &GestionnairePostmaster, response_local: Response, fuuid: &str, url: &str) -> Result<u16, Box<dyn Error>> {

        let stream_state_rc = Arc::new(Mutex::new(Some(StreamState {reponse: response_local, position: 0, chunk_overlap: None})));
        loop  {
            let position_courante = {
                // Extraire position courante
                let guard = stream_state_rc.lock().expect("lock");
                guard.as_ref().expect("stream state").position
            };
            let iter = read_to_substream(stream_state_rc.clone());
            let body = Body::wrap_stream(iter);

            debug!("upload_split Uploader part position {}", position_courante);
            let reponse_part = connecter_remote(gestionnaire, url, fuuid, Some(position_courante), body).await?;

            let status = reponse_part.status();
            let status_code = status.as_u16();
            if status.is_success() {
                debug!("Reponse part (status: {}) {:?}", status_code, reponse_part);
                match reponse_part.json::<ResponsePutFichierPartiel>().await {
                //match reponse_part.text().await {
                    Ok(inner) => {
                        debug!("Reponse part : {:?}", inner);
                    },
                    Err(e) => error!("upload_split Erreur verification reponse : {:?}", e)
                }
            } else if status_code == 409 {
                match reponse_part.headers().get("x-position") {
                    Some(position) => {
                        match position.to_str() {
                            Ok(position_str) => {
                                debug!("transfert_fichier.upload_split Resume (http 409), position courante {}", position_str);
                                todo!("Fix me");
                            },
                            Err(e) => {
                                error!("transfert_fichier.upload_split Erreur parse position str, abort : {:?}", e);
                                Err(e)?;
                            }
                        }
                    },
                    None => Err(format!("transfert_fichier.upload_split HTTP 409 sans position"))?
                }
            } else {
                Err(format!("transfert_fichier.upload_split Echec upload fichier split {} : http status {}", fuuid, reponse_part.status().as_u16()))?;
            }

            debug!("upload_split Reponse put : {}", status_code);
            {
                if stream_state_rc.lock().expect("lock").is_none() {
                    debug!("upload_split Upload termine");
                    break;
                }
            }
        }

        let reponse_finale = upload_post_final(gestionnaire, url, fuuid).await?;
        let status_final = reponse_finale.status();
        match status_final.is_success() {
            true => {
                let contenu: ResponsePutFichierPartiel = reponse_finale.json().await?;
                debug!("Reponse finale contenu (status: {}) : {:?}", status_final.as_u16(), contenu);
                if contenu.ok {
                    Ok(status_final.as_u16())
                } else {
                    Err(format!("Erreur confirmation fichier, err : {:?}", contenu.err))?
                }
            },
            false => Err(format!("transfert_fichier.upload_split Erreur POST upload fichier {}", reponse_finale.status().as_u16()))?
        }
    }

}

async fn upload_post_final(gestionnaire: &GestionnairePostmaster, url: &str, fuuid: &str)
    -> Result<Response, Box<dyn Error>>
{
    // let client = gestionnaire.http_client_remote.as_ref().expect("client reqwest fichiers remote");
    let client = get_client(&gestionnaire, url)?;

    let mut url_post_fichier = Url::parse(url)?;
    let url_liste_fichiers_str = format!("{}/poster/{}", url_post_fichier.path(), fuuid);
    url_post_fichier.set_path(url_liste_fichiers_str.as_str());

    let response = client.post(url_post_fichier).send().await?;

    Ok(response)
}

pub struct StreamState {
    pub reponse: Response,
    pub position: usize,
    pub chunk_overlap: Option<bytes::Bytes>,
}

// https://stackoverflow.com/questions/58700741/is-there-any-way-to-create-a-async-stream-generator-that-yields-the-result-of-re
fn read_to_substream(stream_state_rc: Arc<Mutex<Option<StreamState>>>) -> impl futures::TryStream<Ok = bytes::Bytes, Error = String> {

    let compteur = 0;
    // Extraire une version owned the stream_state, va etre passe dans le state
    let inner_stream_state = stream_state_rc.lock().expect("lock").take().expect("take");

    futures::stream::unfold((inner_stream_state, stream_state_rc, compteur), |state| async move {
        let (mut inner_stream_state, stream_state_rc, compteur)  = state;

        // Prendre prochain chunk - utiliser overlap si disponible, sinon stream
        let chunk = match inner_stream_state.chunk_overlap.take() {
            Some(b) => {
                // debug!("read_to_substream Take overlap len {}", b.len());
                Some(b)
            },
            None => match inner_stream_state.reponse.chunk().await {
                Ok(c) => {
                    // if let Some(b) = c.as_ref() {
                    //     debug!("read_to_substream Read stream input {}", b.len());
                    // }
                    c
                },
                Err(e) => {
                    error!("read_to_substream erreur {:?}", e);
                    return None
                }
            }
        };

        match chunk {
            Some(b) => {
                let compteur_chunk = compteur + b.len();

                if compteur_chunk <= MESSAGE_SIZE_LIMIT - BUFFER_SIZE as usize {
                    inner_stream_state.position += b.len();
                    Some((Ok(b), (inner_stream_state, stream_state_rc, compteur_chunk)))
                } else {
                    // Remettre reponse dans le mutex pour prochaine batch
                    debug!("read_to_substream Part complet lu : {} bytes, overlap {}", compteur, b.len());
                    inner_stream_state.chunk_overlap = Some(b);
                    let mut guard = stream_state_rc.lock().expect("lock");
                    *guard = Some(inner_stream_state);
                    None
                }
            },
            None => None
        }
    })

}

/// Mettre les destinations en ordre (TOR en premier si disponible)
pub fn trier_destinations<'a>(gestionnaire: &GestionnairePostmaster, fiche: &'a FicheMillegrilleApplication) -> Vec<&'a FicheApplication> {
    let tor_disponible = gestionnaire.http_client_tor.is_some();
    let mut destinations = Vec::new();
    for app_config in &fiche.application {
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

#[cfg(test)]
mod reqwest_stream_tests {
    use std::error::Error;
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

        let stream_state_rc = Arc::new(Mutex::new(Some(StreamState {reponse, position: 0, chunk_overlap: None})));

        loop  {
            let position = {
                // Extraire position courante
                let guard = stream_state_rc.lock().expect("lock");
                guard.as_ref().expect("stream state").position
            };
            let iter = read_to_substream(stream_state_rc.clone());
            let body = Body::wrap_stream(iter);
            let url_put = Url::parse(format!("http://mg-dev1.maple.maceroc.com:3033/fichiers/test1/{}", position).as_str())
                .expect("url");
            let reponse_put = client_remote.put(url_put)
                .header("Content-Type", "application/stream")
                .body(body)
                .send().await.expect("put");
            debug!("Reponse put : {:?}", reponse_put);
            {
                if stream_state_rc.lock().expect("lock").is_none() {
                    debug!("Upload termine");
                    break;
                }
            }
        }

    }

}
