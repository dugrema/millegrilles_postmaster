use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use log::{debug, error, info, warn};

use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::{charger_configuration, ConfigMessages, IsConfigNoeud};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::domaines::GestionnaireMessages;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::{EmetteurCertificat, IsConfigurationPki, MiddlewareMessage, preparer_middleware_message};
use millegrilles_common_rust::tokio::{sync::{mpsc, mpsc::{Receiver, Sender}}, time::{Duration as DurationTokio, timeout}};
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::rabbitmq_dao::{Callback, EventMq, QueueType};
use millegrilles_common_rust::recepteur_messages::TypeMessage;

use crate::gestionnaire::*;

static mut POSTMASTER: TypeGestionnaire = TypeGestionnaire::None;

pub async fn run() {
    // Wiring
    let (mut futures, _) = build().await;

    // Run
    info!("domaines_messagerie: Demarrage traitement, top level threads {}", futures.len());
    let arret = futures.next().await;
    info!("domaines_messagerie: Fermeture du contexte, task daemon terminee : {:?}", arret);
}

/// Enum pour distinger les types de gestionnaires.
#[derive(Clone, Debug)]
enum TypeGestionnaire {
    PostmasterPublic(Arc<GestionnairePostmaster>),
    None
}

/// Conserve les gestionnaires dans la variable 'static
fn charger_gestionnaire(gestionnaire: GestionnairePostmaster) -> &'static TypeGestionnaire {
    // Inserer les gestionnaires dans la variable static - permet d'obtenir lifetime 'static
    unsafe {
        POSTMASTER = TypeGestionnaire::PostmasterPublic(Arc::new(gestionnaire));
        &POSTMASTER
    }
}

// async fn build(gestionnaire: &'static TypeGestionnaire) -> (FuturesUnordered<JoinHandle<()>>, Arc<MiddlewareMessage>) {
async fn build() -> (FuturesUnordered<JoinHandle<()>>, Arc<MiddlewareMessage>) {

    let mut gestionnaire_mut = GestionnairePostmaster::new();

    // Recuperer configuration des Q de tous les domaines
    let queues = {
        let mut queues: Vec<QueueType> = Vec::new();
        queues.extend(gestionnaire_mut.preparer_queues());
        debug!("Queues a preparer : {:?}", queues);
        queues
    };

    // Listeners de connexion MQ
    let (tx_entretien, rx_entretien) = mpsc::channel(1);
    let listeners = {
        let mut callbacks: Callback<EventMq> = Callback::new();
        callbacks.register(Box::new(move |event| {
            debug!("Callback sur connexion a MQ, event : {:?}", event);
            let tx_ref = tx_entretien.clone();
            let _ = spawn(async move {
                match tx_ref.send(event).await {
                    Ok(_) => (),
                    Err(e) => error!("Erreur queuing via callback : {:?}", e)
                }
            });
        }));

        Some(Mutex::new(callbacks))
    };

    let middleware_hooks = preparer_middleware_message(queues, listeners, Securite::L1Public);
    let middleware = middleware_hooks.middleware;

    // Wiring final du gestionnaire
    let gestionnaire_static = match new_client_local(middleware.get_enveloppe_privee().as_ref()) {
        Ok(client_local) => {
            gestionnaire_mut.http_client_local = Some(client_local);
            match new_client_remote() {
                Ok(client_remote) => {
                    gestionnaire_mut.http_client_remote = Some(client_remote);
                    charger_gestionnaire(gestionnaire_mut)
                },
                Err(e) => panic!("Erreur creation client reqwest pour fichiers remote : {:?}", e)
            }
        },
        Err(e) => panic!("Erreur creation client reqwest pour fichiers locaux : {:?}", e)
    };

    // Preparer les green threads de tous les domaines/processus
    let mut futures = FuturesUnordered::new();
    {
        let mut map_senders: HashMap<String, Sender<TypeMessage>> = HashMap::new();

        // ** Gestionnaires **
        {
            let (
                routing_g,
                futures_g,
            ) = match gestionnaire_static {
                TypeGestionnaire::PostmasterPublic(g) => {
                    g.preparer_threads(middleware.clone()).await.expect("gestionnaire")
                },
                TypeGestionnaire::None => (HashMap::new(), FuturesUnordered::new()),
            };
            futures.extend(futures_g);        // Deplacer vers futures globaux
            map_senders.extend(routing_g);    // Deplacer vers mapping global
        }

        // ** Wiring global **

        // Creer consommateurs MQ globaux pour rediriger messages recus vers Q internes appropriees
        futures.push(spawn(
            consommer(middleware.clone(), middleware_hooks.rx_messages_verifies, map_senders.clone())
        ));
        futures.push(spawn(
            consommer(middleware.clone(), middleware_hooks.rx_messages_verif_reply, map_senders.clone())
        ));
        futures.push(spawn(
            consommer(middleware.clone(), middleware_hooks.rx_triggers, map_senders.clone())
        ));

        // ** Thread d'entretien **
        futures.push(spawn(entretien(middleware.clone(), rx_entretien, vec![gestionnaire_static])));

        // Thread ecoute et validation des messages
        for f in middleware_hooks.futures {
            futures.push(f);
        }
    }

    debug!("Futures a demarrer : {:?}", futures);

    (futures, middleware)
}

async fn consommer<M>(
    _middleware: Arc<M>,
    mut rx: Receiver<TypeMessage>,
    map_senders: HashMap<String, Sender<TypeMessage>>
)
    where M: ValidateurX509 + GenerateurMessages
{
    info!("consommer : Debut thread, mapping : {:?}", map_senders.keys());

    while let Some(message) = rx.recv().await {
        match &message {
            TypeMessage::Valide(m) => {
                warn!("consommer: Message valide sans routing key/action : {:?}", m.message);
            },
            TypeMessage::ValideAction(m) => {
                let contenu = &m.message;
                let rk = m.routing_key.as_str();
                let action = m.action.as_str();
                let domaine = m.domaine.as_str();
                let nom_q = m.q.as_str();
                info!("consommer: Traiter message valide (action: {}, rk: {}, q: {})", action, rk, nom_q);
                debug!("consommer: Traiter message valide contenu {:?}", contenu);

                // Tenter de mapper avec le nom de la Q (ne fonctionnera pas pour la Q de reponse)
                let sender = match map_senders.get(nom_q) {
                    Some(sender) => {
                        debug!("consommer Mapping message avec nom_q: {}", nom_q);
                        sender
                    },
                    None => {
                        match map_senders.get(domaine) {
                            Some(sender) => {
                                debug!("consommer Mapping message avec domaine: {}", domaine);
                                sender
                            },
                            None => {
                                error!("consommer Message de queue ({}) et domaine ({}) inconnu, on le drop", nom_q, domaine);
                                continue  // On skip
                            },
                        }
                    }
                };

                match sender.send(message).await {
                    Ok(()) => (),
                    Err(e) => {
                        error!("consommer Erreur consommer message {:?}", e)
                    }
                }
            },
            TypeMessage::Certificat(_) => (),  // Rien a faire
            TypeMessage::Regeneration => (),   // Rien a faire
        }
    }

    info!("consommer: Fin thread : {:?}", map_senders.keys());
}

/// Thread d'entretien
async fn entretien<M>(middleware: Arc<M>, mut rx: Receiver<EventMq>, gestionnaires: Vec<&'static TypeGestionnaire>)
    where M: ValidateurX509 + GenerateurMessages + EmetteurCertificat
{
    info!("Debut thread entretien");
    let mut certificat_emis = false;

    loop {
        sleep(Duration::new(30, 0)).await;
        if certificat_emis == false {
            debug!("entretien Emettre certificat");
            match middleware.emettre_certificat(middleware.as_ref()).await {
                Ok(()) => certificat_emis = true,
                Err(e) => error!("entretien Erreur emission certificat local : {:?}", e),
            }
            debug!("entretien Fin emission traitement certificat local, resultat : {}", certificat_emis);
        }

        middleware.entretien_validateur().await;
    }

    info!("Fin thread entretien");
}
