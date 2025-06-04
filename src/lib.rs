use std::pin::Pin;
use cxx::{bridge, let_cxx_string};
use openfhe::cxx::{CxxString,CxxVector, UniquePtr};
use openfhe::{cxx, ffi as ffi};
use openfhe::ffi::{CryptoContextDCRTPoly, KeyPairDCRTPoly, ParamsBFVRNS, ParamsCKKSRNS, PublicKeyDCRTPoly, DCRTPolySerializePublicKeyToString, DCRTPolyDeserializePublicKeyFromString, DCRTPolyGenNullPublicKey, CiphertextDCRTPoly, DCRTPolySerializeCiphertextToString};



pub struct HomomorphicIntegers {
    _cc_params_ckksrns: cxx::UniquePtr<ParamsCKKSRNS>,
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
        let _mult_depth: u32 = 1;
        let _scale_mod_size: u32 = 50;
        let _batch_size: u32 = 8;

        let mut _cc_params_ckksrns = ffi::GenParamsCKKSRNS();
        _cc_params_ckksrns.pin_mut().SetMultiplicativeDepth(_mult_depth);
        _cc_params_ckksrns.pin_mut().SetScalingModSize(_scale_mod_size);
        _cc_params_ckksrns.pin_mut().SetBatchSize(_batch_size);

        let _cc = ffi::DCRTPolyGenCryptoContextByParamsCKKSRNS(&_cc_params_ckksrns);
        _cc.EnableByFeature(ffi::PKESchemeFeature::PKE);
        _cc.EnableByFeature(ffi::PKESchemeFeature::KEYSWITCH);
        _cc.EnableByFeature(ffi::PKESchemeFeature::LEVELEDSHE);
        // generate keypair
        let mut key_pair = _cc.KeyGen();
        HomomorphicIntegers {
            _cc_params_ckksrns,
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
    
    pub fn get_serialized_jsonkey(&mut self, pkey : &UniquePtr<PublicKeyDCRTPoly>) -> String{
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

    pub fn get_serialized_cipher_text(&mut self, cipher : &UniquePtr<CiphertextDCRTPoly>)  -> String{
        let serialized_json_key = DCRTPolySerializeCiphertextToString(&cipher);
        return convert_to_rust_string(serialized_json_key);
    }
    pub fn get_cipher_text(&mut self,pkey : &UniquePtr<PublicKeyDCRTPoly>, val: Option<f64>) -> UniquePtr<CiphertextDCRTPoly>{
        let mut odometer = CxxVector::<f64>::new();
        odometer.pin_mut().push(val.unwrap());
        
        let _dcrt_poly_params = ffi::DCRTPolyGenNullParams();
        let packed_text = self._cc.MakeCKKSPackedPlaintextByVectorOfDouble(&odometer, 1, 0, &_dcrt_poly_params, 0);

       return self._cc.EncryptByPublicKey(pkey, &packed_text);
    }
    
    
}

