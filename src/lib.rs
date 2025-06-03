use std::pin::Pin;
use cxx::{bridge, let_cxx_string};
use openfhe::cxx::{CxxString,CxxVector, UniquePtr};
use openfhe::{cxx, ffi as ffi};
use openfhe::ffi::{CryptoContextDCRTPoly, KeyPairDCRTPoly, ParamsBFVRNS, ParamsCKKSRNS, PublicKeyDCRTPoly, 
                   DCRTPolySerializePublicKeyToString, DCRTPolyDeserializePublicKeyFromString, DCRTPolyGenNullPublicKey};



pub struct HomomorphicIntegers {
      _cc_params_bfvrns: cxx::UniquePtr<ParamsBFVRNS>,
      _cc: cxx::UniquePtr<CryptoContextDCRTPoly>,
      key_pair:  Option<cxx::UniquePtr<KeyPairDCRTPoly>>
}

fn convert_to_rust_string(cpp_string: UniquePtr<CxxString>) -> String {
    cpp_string
        .as_ref()                     // Convert UniquePtr<CxxString> to &CxxString
        .expect("C++ string was null")
        .to_str()                     // Convert &CxxString to &str
        .expect("Invalid UTF-8 in C++ string")
        .to_owned()                   // Convert &str to Rust-owned String
}


impl HomomorphicIntegers {
    pub fn new() -> Self {
        // Init the integer homo_m_module
        let mut _cc_params_bfvrns = ffi::GenParamsBFVRNS();
        // setup the ring
        _cc_params_bfvrns.pin_mut().SetPlaintextModulus(65537);
        _cc_params_bfvrns.pin_mut().SetMultiplicativeDepth(2);
        let mut _cc = ffi::DCRTPolyGenCryptoContextByParamsBFVRNS(&_cc_params_bfvrns);
        // prata senare
        _cc.EnableByFeature(ffi::PKESchemeFeature::PKE);
        _cc.EnableByFeature(ffi::PKESchemeFeature::KEYSWITCH);
        _cc.EnableByFeature(ffi::PKESchemeFeature::LEVELEDSHE);
        // generate keypair
        let mut key_pair = _cc.KeyGen();
        HomomorphicIntegers {
            _cc_params_bfvrns,
            _cc,
            key_pair:None,
        }
    }
    
    pub fn genkeypair(&mut self){
        let mut key_pair = self._cc.KeyGen();
        // let mut pub_key = &key_pair.GetPublicKey(); 
        self.key_pair = Some(key_pair);
    }
    
  pub fn getpubkey(&self) -> UniquePtr<PublicKeyDCRTPoly> {
        return self.key_pair.as_ref().expect("key pair not initialized").GetPublicKey();
    }
    
    pub fn get_serialized_jsonkey(self, pkey : &UniquePtr<PublicKeyDCRTPoly>) -> String{
        let mut serialized_json_key = DCRTPolySerializePublicKeyToString(&pkey);
        return convert_to_rust_string(serialized_json_key);
    }
    
    pub fn get_deserialized_jsonkey(self, pkey: Pin<&mut PublicKeyDCRTPoly>, serialized_jsokey : String){
        let_cxx_string!(cxx_json = serialized_jsokey);
        DCRTPolyDeserializePublicKeyFromString(pkey, &*cxx_json);
    }
    
    pub fn get_pinned_empty_public_key(&mut self) -> cxx::UniquePtr<PublicKeyDCRTPoly> {
        return DCRTPolyGenNullPublicKey()
    }
}

