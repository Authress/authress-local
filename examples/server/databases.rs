use std::{collections::HashMap, sync::Arc, sync::Mutex};
use authress::models::*;

use crate::authentication::SignatureKey;

type AccessRecordDb = Arc<Mutex<HashMap<String, AccessRecord>>>;

pub struct Databases {
    pub records_db: AccessRecordDb,
    pub groups_db: Arc<Mutex<HashMap<String, Group>>>,
    pub roles_db: Arc<Mutex<HashMap<String, Role>>>,
    pub signature_key: Arc<Mutex<SignatureKey>>
}

impl Default for Databases {
    fn default() -> Databases {
        return Databases {
            records_db: Arc::new(Mutex::new(HashMap::new())),
            groups_db: Arc::new(Mutex::new(HashMap::new())),
            roles_db: Arc::new(Mutex::new(HashMap::new())),
            signature_key: Arc::new(Mutex::new(SignatureKey::default()))
        };
    }
}