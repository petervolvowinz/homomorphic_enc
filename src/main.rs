// Defines the server that "requests" encrypted data. 

// mod bin::client;

use std::io::ErrorKind::HostUnreachable;
use std::pin::Pin;
use cxx::CxxVector;
use homomorphic_enc::HomomorphicFloats;
use homomorphic_enc::print_delay;

use tonic::{transport::Server, Request, Response, Status};

const RATE_KM: f64 = 0.2; // in some currency
const FEE: f64 = 100.0;  // Some fee related to a fleet
const MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024;

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
        
        print_delay("request to calculate cost recieved");
        let mut homomorphic = HomomorphicFloats::new();
        homomorphic.genkeypair();
        print_delay("deserializing");
        let mut serialized_key = request.get_ref().pub_key.as_str();
        let mut pkey = homomorphic.get_pinned_empty_public_key();
        let pinned_key = pkey.as_mut().expect("public key allocation failed");

        let mut eval_keys = request.get_ref().mul_eval_keys.as_str();
        homomorphic.get_deserialized_eval_keys(eval_keys.to_string());
        homomorphic.get_deserialized_jsonkey(pinned_key, serialized_key.to_string());
        // setup the float vectors for fee and rate.
        print_delay("encrypting fee and rate");
        let mut rate_v = CxxVector::<f64>::new();
        rate_v.pin_mut().push(RATE_KM);

        let mut fee_v = CxxVector::<f64>::new();
        fee_v.pin_mut().push(FEE);
        let rate_cipher = homomorphic.get_cypher_text_from_double_vector(&pkey,rate_v);
        let fee_cipher = homomorphic.get_cypher_text_from_double_vector(&pkey,fee_v);


        // encrypt with sent public key

        // retrieve the encrypted traveled distance from "vehicle"
        let mut odometer_enc = request.get_ref().vss_odometer_cipher.as_str();
        let mut cipher_text_dist  = homomorphic.get_empty_cipher_text();
        homomorphic.get_deserialized_cipher_text(cipher_text_dist.pin_mut(),odometer_enc.parse::<String>().unwrap());
        
        print_delay("calculating cost on encrypted data");
        let cost_cipher = homomorphic.get_cost_cipher(rate_cipher, fee_cipher,cipher_text_dist);
        let serialzed_cost = homomorphic.get_serialized_cipher_text(&cost_cipher);
        print_delay("sending encrypted response to vehicle");
        let response = EncResult {
            cost_cipher:  serialzed_cost,
        };

        Ok(Response::new(response))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let service = MyEncryptionService::default();

    let message = format!("EncryptionServiceServer listening on {}", addr);
    print_delay(&message);
    let homomorphic = HomomorphicFloats::new();
    // let mut pubkey = homomorphic.getpubkey();


    let configured_service = EncryptionServiceServer::new(service)
        .max_decoding_message_size(MAX_MESSAGE_SIZE) // Limits incoming messages for this service
        .max_encoding_message_size(MAX_MESSAGE_SIZE);
    
    Server::builder()
        .add_service(configured_service)
        .serve(addr)
        .await?;

    Ok(())
}
