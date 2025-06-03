// Defines the server that "requests" encrypted data. 

// mod bin::client;

use std::io::ErrorKind::HostUnreachable;
use std::pin::Pin;
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
        
        let mut homomorphic = HomomorphicIntegers::new();
        let mut serialized_key = request.get_ref().pub_key.as_str();
        let mut pkey = homomorphic.get_pinned_empty_public_key();
        let pinned_key = pkey.as_mut().expect("public key allocation failed");
         
        homomorphic.get_deserialized_jsonkey(pinned_key, serialized_key.parse().unwrap());
        //TODO use pinned_key to encrypt fee and rate here..
        
        
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
