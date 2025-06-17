use cxx::CxxVector;
use openfhe::ffi;
use tonic::transport::Channel;
use encryption::encryption_service_client::EncryptionServiceClient;
use encryption::EncryptedData;
use homomorphic_enc::HomomorphicFloats;



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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = Channel::from_static("http://[::1]:50051")
        .connect()
        .await?;

    let mut client = EncryptionServiceClient::new(channel)
        .max_decoding_message_size(MAX_MESSAGE_SIZE)
        .max_encoding_message_size(MAX_MESSAGE_SIZE);
    
    let mut vss_signal = VssSignal::new("TraveledDistance".to_string(), Option::from(55.3));

    
    // get a public key and Serialize
   let mut homomorphic = HomomorphicFloats::new();
   homomorphic.genkeypair();
   let mut pkey = homomorphic.getpubkey();

    let mut current_distance_trav = CxxVector::<f64>::new();
    current_distance_trav.pin_mut().push(vss_signal.value.unwrap());
    
   // get the cipher 
   let cipher_text =  homomorphic.get_cypher_text_from_double_vector(&pkey,current_distance_trav);
   let json_key = homomorphic.get_serialized_jsonkey(&pkey);
   let serialized_cipher = homomorphic.get_serialized_cipher_text(&cipher_text); 
   let eval_keys  = homomorphic.get_serialized_eval_keys();
    // get the multiplication  eval keys.
    
    
    let request = tonic::Request::new(EncryptedData {
        vss_odometer_cipher: serialized_cipher,
        pub_key: json_key,
        mul_eval_keys : eval_keys
    });
    let response = client.process_encrypted_data(request).await?;

    let mut cipher_text_dist  = homomorphic.get_empty_cipher_text();
    homomorphic.get_deserialized_cipher_text(cipher_text_dist.pin_mut(),response.into_inner().cost_cipher);
    
    let mut res = homomorphic.get_decrypted_cost_from_result_cipher(cipher_text_dist);
    
    println!("current cost is = {}", res);
    Ok(())
}
