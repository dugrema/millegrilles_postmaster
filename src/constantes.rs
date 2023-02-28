pub const DOMAINE_NOM: &str = "postmaster";
pub const DOMAINE_TOPOLOGIE: &str = "CoreTopologie";
pub const DOMAINE_MESSAGERIE: &str = "Messagerie";

pub const REQUETE_APPLICATIONS_TIERS: &str = "applicationsTiers";

pub const COMMANDE_POSTER: &str = "poster";
pub const COMMANDE_POUSSER_ATTACHMENT: &str = "pousserAttachment";
pub const COMMANDE_PROCHAIN_ATTACHMENT: &str = "prochainAttachment";
pub const COMMANDE_POST_NOTIFICATION: &str = "postNotification";

pub const EVENEMENT_UPLOAD_ATTACHMENT: &str = "evenementAttachment";
pub const COMMANDE_UPLOAD_ATTACHMENT: &str = "uploadAttachment";

pub const NOM_Q_VOLATILS: &str = "postmaster/volatils";
pub const NOM_Q_TRIGGERS: &str = "postmaster/triggers";

pub const CODE_UPLOAD_DEBUT: u32 = 1;
pub const CODE_UPLOAD_ENCOURS: u32 = 2;
pub const CODE_UPLOAD_TERMINE: u32 = 3;
pub const CODE_UPLOAD_ERREUR: u32 = 4;

pub const WEBPUSH_ENCODING_AES128: &str = "aes128gcm";
pub const WEBPUSH_HEADER_AUTHORIZATION: &str = "Authorization";