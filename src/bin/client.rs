use encryption::encryption_service_client::EncryptionServiceClient;
use encryption::EncryptedData;
use homomorphic_enc::HomomorphicFloats;


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
    let mut client = EncryptionServiceClient::connect("http://[::1]:50051").await?;
    let mut signal = VssSignal::new("TraveledDistance".to_string(), Option::from(55.3));

    
    // get a public key and Serialize
   let mut homomorphic = HomomorphicFloats::new();
   homomorphic.genkeypair();
   let mut pkey = homomorphic.getpubkey();
  
   let cipher_text =  homomorphic.get_cipher_text(&pkey, signal.value);
   let json_key = homomorphic.get_serialized_jsonkey(&pkey);
   let serialized_cipher = homomorphic.get_serialized_cipher_text(&cipher_text);
    
    let request = tonic::Request::new(EncryptedData {
        vss_odometer_cipher: serialized_cipher,
        pub_key: json_key
    });
    let response = client.process_encrypted_data(request).await?;
    
    println!("RESPONSE = {:?}", response.into_inner().cost_cipher);

    Ok(())
}
