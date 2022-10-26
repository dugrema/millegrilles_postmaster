use std::error::Error;
use std::sync::Arc;

use log::{debug, error, info, warn};

use millegrilles_common_rust::constantes::{DEFAULT_Q_TTL, Securite};
use millegrilles_common_rust::domaines::GestionnaireMessages;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::MiddlewareMessages;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::certificats::EnveloppePrivee;
use millegrilles_common_rust::configuration::ConfigurationNoeud;
use millegrilles_common_rust::reqwest;
use millegrilles_common_rust::reqwest::Client;
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use crate::commandes::consommer_commande;

use crate::constantes::*;
use crate::evenements::consommer_evenement;
use crate::requetes::consommer_requete;

#[derive(Debug)]
pub struct GestionnairePostmaster {
    // tx_pompe_messages: Mutex<Option<Sender<MessagePompe>>>,
    pub http_client_local: Option<Client>,
    pub http_client_remote: Option<Client>,
    pub http_client_tor: Option<Client>,
}

#[async_trait]
impl GestionnaireMessages for GestionnairePostmaster {
    fn get_nom_domaine(&self) -> String {
        DOMAINE_NOM.into()
    }

    fn get_q_volatils(&self) -> String {
        NOM_Q_VOLATILS.into()
    }

    fn get_q_triggers(&self) -> String {
        NOM_Q_TRIGGERS.into()
    }

    fn preparer_queues(&self) -> Vec<QueueType> {
        preparer_queues()
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: MiddlewareMessages + 'static
    {
        consommer_requete(middleware, message, &self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: MiddlewareMessages + 'static
    {
        consommer_commande(middleware, message, &self).await
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: MiddlewareMessages + 'static
    {
        consommer_evenement(self, middleware, message).await
    }

    async fn entretien<M>(&self, middleware: Arc<M>) where M: MiddlewareMessages + 'static {
        info!("gestionnaire Debut thread entretien");
        loop {
            sleep(Duration::new(30, 0)).await;
        }
        info!("gestionnaire Fin thread entretien");
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule) -> Result<(), Box<dyn Error>> where M: MiddlewareMessages + 'static {
        if let Err(e) = traiter_cedule(self, middleware, trigger).await {
            error!("traiter_cedule Erreur traitement cedule : {:?}", e);
        };

        Ok(())
    }
}

impl Clone for GestionnairePostmaster {
    fn clone(&self) -> Self {
        GestionnairePostmaster {
            http_client_local: self.http_client_local.clone(),
            http_client_remote: self.http_client_remote.clone(),
            http_client_tor: self.http_client_tor.clone(),
        }
    }
}

impl GestionnairePostmaster {
    pub fn new() -> GestionnairePostmaster {
        return GestionnairePostmaster {
            http_client_local: None,
            http_client_remote: None,
            http_client_tor: None,
        }
    }

    pub fn preparer_queues(&self) -> Vec<QueueType> {
        preparer_queues()
    }
}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();
    //let mut rk_sauvegarder_cle = Vec::new();

    // RK 1.public
    let commandes_publiques: Vec<&str> = vec![
        COMMANDE_POSTER,
        COMMANDE_POUSSER_ATTACHMENT,
    ];
    for cmd in commandes_publiques {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L1Public});
    }

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_VOLATILS.into(),
            routing_keys: rk_volatils,
            ttl: DEFAULT_Q_TTL.into(),
            durable: true,
            autodelete: false,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into(), Securite::L1Public));

    queues
}

pub async fn traiter_cedule<M>(gestionnaire: &GestionnairePostmaster, middleware: &M, trigger: &MessageCedule)
                               -> Result<(), Box<dyn Error>>
    where M: MiddlewareMessages + 'static
{
    debug!("Traiter cedule {}", DOMAINE_NOM);

    // let mut prochain_entretien_index_media = chrono::Utc::now();
    // let intervalle_entretien_index_media = chrono::Duration::minutes(5);

    // let date_epoch = trigger.get_date();
    // let minutes = date_epoch.get_datetime().minute();

    // Executer a toutes les 5 minutes
    // if minutes % 5 == 0 {
    // }

    Ok(())
}

pub fn new_client_local(enveloppe_privee: &EnveloppePrivee) -> Result<Client, Box<dyn Error>> {
    let ca_cert_pem = match enveloppe_privee.chaine_pem().last() {
        Some(cert) => cert.as_str(),
        None => Err(format!("transfert_fichier.transferer_fichier Certificat CA manquant"))?,
    };
    let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;
    let identity = reqwest::Identity::from_pem(enveloppe_privee.clecert_pem.as_bytes())?;

    let client = reqwest::Client::builder()
        .add_root_certificate(root_ca)
        .identity(identity)
        .https_only(true)
        .use_rustls_tls()
        // .http1_only()
        .http2_adaptive_window(true)
        .build()?;

    Ok(client)
}

pub fn new_client_remote() -> Result<Client, Box<dyn Error>> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .use_rustls_tls()
        .http2_adaptive_window(true)
        .danger_accept_invalid_certs(true)  // Millegrille tierce
        .build()?;
    Ok(client)
}

pub fn new_client_tor(configuration: &ConfigurationNoeud) -> Option<Client> {

    let url_proxy = match &configuration.tor_proxy {
        Some(inner) => inner,
        None => return None
    };

    let proxy = match reqwest::Proxy::https(url_proxy.clone()) {
        Ok(inner) => inner,
        Err(e) => {
            warn!("Erreur adresse proxy TOR ({}), tor ne sera pas disponible : {:?}", url_proxy, e);
            return None
        }
    };

    let builder = reqwest::Client::builder().https_only(true)
        .use_rustls_tls()
        .http2_adaptive_window(true)
        .danger_accept_invalid_certs(true)  // Millegrille tierce
        .proxy(proxy);

    match builder.build() {
        Ok(inner) => Some(inner),
        Err(e) => {
            warn!("Erreur creation proxy TOR (.onion), tor ne sera pas disponible : {:?}", e);
            None
        }
    }

}
