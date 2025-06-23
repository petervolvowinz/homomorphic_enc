use std::thread::sleep;
use std::time::Duration;
use cxx::CxxVector;
use openfhe::ffi;
use tonic::transport::Channel;
use encryption::encryption_service_client::EncryptionServiceClient;
use encryption::EncryptedData;
use homomorphic_enc::{print_delay, HomomorphicFloats};



const MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024;
// A VSS based signal where all values are being treated as string for simplicity
pub struct VssSignal {
    name: String,
    value: Option<f64>
} 

impl VssSignal{
       fn new(name: String, value: Option<f64>) -> VssSignal {
           return VssSignal {name, value} ;
       }
}

pub mod encryption {
    tonic::include_proto!("encryption");
}


// Connect to server using 5 retries...
async fn connect_with_retries() -> Result<Channel, Box<dyn std::error::Error>> {
    let mut attempts = 0;
    let max_attempts = 5;
    let delay = Duration::from_secs(1);

    loop {
        attempts += 1;
        match Channel::from_static("http://[::1]:50051")
            .connect()
            .await
        {
            Ok(channel) => return Ok(channel),
            Err(e) if attempts < max_attempts => {
                eprintln!("Connection attempt {} failed: {}. Retrying...", attempts, e);
                sleep(delay);
            }
            Err(e) => {
                eprintln!("Connection attempt {} failed: {}. Giving up !", attempts, e);
                return Err(Box::new(e));
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_delay("connect to server");
    let channel = connect_with_retries().await?;

    let mut client = EncryptionServiceClient::new(channel)
        .max_decoding_message_size(MAX_MESSAGE_SIZE)
        .max_encoding_message_size(MAX_MESSAGE_SIZE);
    
    let mut vss_signal = VssSignal::new("TraveledDistance".to_string(), Option::from(55.3));

    
    print_delay("encrypting current traveled distance");
    // get a public key and Serialize
   let mut homomorphic = HomomorphicFloats::new();
   homomorphic.genkeypair();
   let mut pkey = homomorphic.getpubkey();

    let mut current_distance_trav = CxxVector::<f64>::new();
    current_distance_trav.pin_mut().push(vss_signal.value.unwrap());
    
   // get the cipher 
   let cipher_text =  homomorphic.get_cypher_text_from_double_vector(&pkey,current_distance_trav);
   print_delay("Serialize pkey, cipher and evalkeys"); 
   let json_key = homomorphic.get_serialized_jsonkey(&pkey);
   let serialized_cipher = homomorphic.get_serialized_cipher_text(&cipher_text); 
   let eval_keys  = homomorphic.get_serialized_eval_keys();
    // get the multiplication  eval keys.
    
    print_delay("send request to server");
    let request = tonic::Request::new(EncryptedData {
        vss_odometer_cipher: serialized_cipher,
        pub_key: json_key,
        mul_eval_keys : eval_keys
    });
    let response = client.process_encrypted_data(request).await?;
    print_delay("receieved response");
    
    let mut cipher_text_dist  = homomorphic.get_empty_cipher_text();
    homomorphic.get_deserialized_cipher_text(cipher_text_dist.pin_mut(),response.into_inner().cost_cipher);
    
    let mut res = homomorphic.get_decrypted_cost_from_result_cipher(cipher_text_dist);
    
    let message = format!("current cost is = {}", res);
    print_delay(&message);
    Ok(())
}
