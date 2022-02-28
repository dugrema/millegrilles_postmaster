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
use millegrilles_common_rust::tokio::time::{Duration, sleep};

use crate::constantes::*;

#[derive(Debug)]
pub struct GestionnairePostmaster {
    // tx_pompe_messages: Mutex<Option<Sender<MessagePompe>>>,
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

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: MiddlewareMessages + 'static {
        todo!()
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: MiddlewareMessages + 'static {
        todo!()
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: MiddlewareMessages + 'static {
        todo!()
    }

    async fn entretien<M>(&self, middleware: Arc<M>) where M: MiddlewareMessages + 'static {
        info!("gestionnaire Debut thread entretien");
        loop {
            sleep(Duration::new(30, 0)).await;
        }
        info!("gestionnaire Fin thread entretien");
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule) -> Result<(), Box<dyn Error>> where M: MiddlewareMessages + 'static {
        todo!()
    }
}

impl Clone for GestionnairePostmaster {
    fn clone(&self) -> Self {
        GestionnairePostmaster {
            // tx_pompe_messages: Mutex::new(Some(self.get_tx_pompe()))
        }
    }
}

impl GestionnairePostmaster {
    pub fn new() -> GestionnairePostmaster {
        return GestionnairePostmaster {
            // tx_pompe_messages: Mutex::new(None)
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
    // let requetes_privees: Vec<&str> = vec![
    //     REQUETE_GET_MESSAGES,
    //     REQUETE_GET_PERMISSION_MESSAGES,
    //     REQUETE_GET_PROFIL,
    //     REQUETE_GET_CONTACTS,
    // ];
    // for req in requetes_privees {
    //     rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L2Prive});
    // }

    let commandes_publiques: Vec<&str> = vec![
        COMMANDE_POSTER,
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
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into()));

    queues
}
