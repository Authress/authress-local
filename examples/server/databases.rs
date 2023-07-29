use std::{collections::HashMap, sync::Arc, sync::Mutex};

use authress::models::AccessRecord;

type AccessRecordDb = Arc<Mutex<HashMap<String, AccessRecord>>>;

pub struct Databases {
    pub records_db: AccessRecordDb
}

impl Default for Databases {
    fn default() -> Databases {
        return Databases {
            records_db: Arc::new(Mutex::new(HashMap::new()))
        };
    }
}