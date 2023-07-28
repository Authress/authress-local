use authress::models::AccessRecord;
use dashmap::DashMap;

pub struct Databases {
    pub records_db: DashMap<String, AccessRecord>
}

impl Default for Databases {
    fn default() -> Databases {
        return Databases {
            records_db: DashMap::<String, AccessRecord>::new()
        };
    }
}