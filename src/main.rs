// Defines the server that "requests" encrypted data. 

// mod bin::client;

use homomorphic_enc::HomomorphicIntegers;

use tonic::{transport::Server, Request, Response, Status};

pub mod encryption {
    tonic::include_proto!("encryption");
}

use encryption::encryption_service_server::{EncryptionService, EncryptionServiceServer};
use encryption::{EncryptedData, Result as EncResult};

#[derive(Default)]
pub struct MyEncryptionService {}

#[tonic::async_trait]
impl EncryptionService for MyEncryptionService {
    async fn process_encrypted_data(
        &self,
        request: Request<EncryptedData>,
    ) -> Result<Response<EncResult>, Status> {
        println!("Got a request: {:?}", request);
        println!("serialized : {:?}", request);
        let response = EncResult {
            cost_cipher: format!("encrypted(cost_from_{})", request.into_inner().vss_odometer_cipher),
        };

        Ok(Response::new(response))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let service = MyEncryptionService::default();

    println!("EncryptionServiceServer listening on {}", addr);
    let homomorphic = HomomorphicIntegers::new(); 
    // let mut pubkey = homomorphic.getpubkey();
    
    Server::builder()
        .add_service(EncryptionServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
