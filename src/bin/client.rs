use encryption::encryption_service_client::EncryptionServiceClient;
use encryption::EncryptedData;
use homomorphic_enc::HomomorphicIntegers;


// A VSS based signal where all values are being treated as string for simplicity
pub struct VssSignal {
    name: String,
    value: Option<i32> 
} 

impl VssSignal{
       fn new(name: String, value: Option<i32>) -> VssSignal {
           return VssSignal {name, value} ;
       }
}

pub mod encryption {
    tonic::include_proto!("encryption");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = EncryptionServiceClient::connect("http://[::1]:50051").await?;

    
    // get a public key and Serialize
   let mut homomorphic = HomomorphicIntegers::new();
   homomorphic.genkeypair();
   let pkey = homomorphic.getpubkey();
   let json_key = homomorphic.get_serialized_jsonkey(&pkey);
    
    
    let request = tonic::Request::new(EncryptedData {
        vss_odometer_cipher: "123456_cipher".into(),
        pub_key: json_key
    });
    let response = client.process_encrypted_data(request).await?;
    
    println!("RESPONSE = {:?}", response.into_inner().cost_cipher);

    Ok(())
}
