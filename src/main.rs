mod postmaster;
mod gestionnaire;
mod constantes;
mod requetes;
mod commandes;
mod evenements;
mod messages_struct;
mod transfert_fichier;

use log::{info};
use millegrilles_common_rust::tokio as tokio;
use crate::postmaster::run;

fn main() {
    env_logger::init();
    info!("Demarrer le contexte");
    executer()
}

#[tokio::main(flavor = "current_thread")]
// #[tokio::main(flavor = "multi_thread", worker_threads = 5)]
async fn executer() {
    run().await
}

#[cfg(test)]
pub mod test_setup {
    use log::{debug};

    pub fn setup(nom: &str) {
        let _ = env_logger::builder().is_test(true).try_init();
        debug!("Running {}", nom);
    }
}
