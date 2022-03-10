use log::{debug, error, info, warn};
use std::error::Error;
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
// for map_err
use millegrilles_common_rust::tokio::io::{AsyncReadExt};

use crate::constantes::*;
use crate::messages_struct::*;

pub async fn uploader_attachment<M>(middleware: &M, fiche: &FicheMillegrilleApplication, fuuid: &str, uuid_message: &str)
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
    transferer_fichier(middleware, fiche, fuuid, uuid_message).await?;

    { // Emettre evenement de confirmation d'upload complete
        let evenement = EvenementUploadAttachment::complete(
            uuid_message.into(), idmg.into(), fuuid.into(), 201);
        emettre_evenement_upload(middleware, evenement).await?;
    }

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

async fn transferer_fichier<M>(middleware: &M, fiche: &FicheMillegrilleApplication, fuuid: &str, uuid_message: &str)
    -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + IsConfigNoeud
{
    let enveloppe_privee = middleware.get_enveloppe_privee();
    let ca_cert_pem = match enveloppe_privee.chaine_pem().last() {
        Some(cert) => cert.as_str(),
        None => Err(format!("Certificat CA manquant"))?,
    };
    let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;
    let identity = reqwest::Identity::from_pem(enveloppe_privee.clecert_pem.as_bytes())?;

    let client_interne = reqwest::Client::builder()
        .add_root_certificate(root_ca)
        .identity(identity)
        .https_only(true)
        .use_rustls_tls()
        // .http1_only()
        .http2_adaptive_window(true)
        .build()?;

    let url_get_fichier = match &middleware.get_configuration_noeud().fichiers_url {
        Some(u) => {
            let mut url_get_fichier = u.clone();
            let url_liste_fichiers_str = format!("/fichiers/{}", fuuid);
            url_get_fichier.set_path(url_liste_fichiers_str.as_str());
            url_get_fichier
        },
        None => Err(format!("URL fichiers n'est pas disponible"))?
    };

    let request_get = client_interne.get(url_get_fichier);
    let reponse = request_get.send().await?;
    debug!("transferer_fichier Reponse : {:?}", reponse);

    let byte_stream = reponse.bytes_stream();
    let mut reader = StreamReader::new(byte_stream.map_err(convert_err));

    let mut hacheur = Hacheur::builder()
        .digester(Code::Blake2b512)
        .base(Base::Base58Btc)
        .build();
    let mut buf = [0; 32768];
    let mut taille_fichier = 0;
    loop {
        let len_read = reader.read(&mut buf).await?;
        taille_fichier += len_read;
        debug!("Data lu : {:?}", len_read);
        if len_read == 0 {
            break;
        }
        hacheur.update(&buf[..len_read]);
    }
    let fuuid_calcule = hacheur.finalize();
    debug!("Fuuid calcule: {}, Taille totale : {}", fuuid_calcule, taille_fichier);
    if fuuid_calcule != fuuid {
        Err(format!("Erreur transfert fichier fuuid : {}, mismatch contenu bytes", fuuid))?;
    }

    Ok(())
}

fn convert_err(err: reqwest::Error) -> std::io::Error {
    todo!()
}