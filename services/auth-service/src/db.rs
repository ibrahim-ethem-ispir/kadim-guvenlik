use mongodb::{Client, options::ClientOptions, Database as MongoDatabase};
use crate::config::Config;

#[derive(Clone, Debug)]
pub struct Database {
    pub client: Client,
    pub db: MongoDatabase,
}

impl Database {
    pub async fn connect(config: &Config) -> mongodb::error::Result<Self> {
        let mut client_options = ClientOptions::parse(&config.mongodb_uri).await?;
        client_options.app_name = Some("kadim-auth-service".to_string());
        
        let client = Client::with_options(client_options)?;
        
        // Ping the database to verify connection
        client
            .database("admin")
            .run_command(mongodb::bson::doc! {"ping": 1}, None)
            .await?;
            
        let db = client.database(&config.mongodb_database);

        // Ensure indexes (unique username)
        let collection = db.collection::<crate::models::User>("users");
        let index_model = mongodb::IndexModel::builder()
            .keys(mongodb::bson::doc! {"username": 1})
            .options(mongodb::options::IndexOptions::builder().unique(true).build())
            .build();
            
        collection.create_index(index_model, None).await?;

        Ok(Database {
            client,
            db,
        })
    }
}
