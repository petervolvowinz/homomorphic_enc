use std::pin::Pin;
use std::{io::{self, Write}, thread, time};
use cxx::{bridge, let_cxx_string};
use openfhe::cxx::{CxxString,CxxVector, UniquePtr};
use openfhe::{cxx, ffi as ffi};
use openfhe::ffi::{CryptoContextDCRTPoly, KeyPairDCRTPoly, ParamsBFVRNS, ParamsCKKSRNS, PublicKeyDCRTPoly, DCRTPolySerializePublicKeyToString, DCRTPolyDeserializePublicKeyFromString, 
                   DCRTPolyGenNullPublicKey, CiphertextDCRTPoly, 
                   DCRTPolySerializeCiphertextToString,DCRTPolyDeserializeCiphertextFromString, DCRTPolyGenNullCiphertext,
                   DCRTPolySerializeEvalMultKeysToString, DCRTPolyDeserializeEvalMultKeysFromString};



pub struct HomomorphicFloats {
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

fn print_with_delay_same_line(s: &str) {
    let delay = time::Duration::from_millis(100);

    for ch in s.chars() {
        print!("{}", ch);
        io::stdout().flush().unwrap(); // flush to make sure it's printed immediately
        thread::sleep(delay);
    } // optional: move to the next line at the end
}

pub fn print_delay(s: &str){
    let dots = "...".to_string();
    print_with_delay_same_line(&dots);
    print_with_delay_same_line(s);
    println!();
}

impl HomomorphicFloats {
    
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
       // let mut key_pair = _cc.KeyGen();
        HomomorphicFloats {
            _cc_params_ckksrns,
            _cc,
            key_pair:None,
        }
    }
    
    pub fn genkeypair(&mut self){
        let key_pair = self._cc.KeyGen();
        // let mut pub_key = &key_pair.GetPublicKey(); '
        self._cc.EvalMultKeyGen(&key_pair.GetPrivateKey());
        self.key_pair = Some(key_pair);
        
    }
    
  pub fn getpubkey(&self) -> UniquePtr<PublicKeyDCRTPoly> {
        return self.key_pair.as_ref().expect("key pair not initialized").GetPublicKey();
    }
    
    pub fn get_serialized_jsonkey(&mut self, pkey : &UniquePtr<PublicKeyDCRTPoly>) -> String{
        let mut serialized_json_key = DCRTPolySerializePublicKeyToString(&pkey);
        return convert_to_rust_string(serialized_json_key);
    }
    
    pub fn get_deserialized_jsonkey(&self, pkey: Pin<&mut PublicKeyDCRTPoly>, serialized_jsokey : String){
        let_cxx_string!(cxx_json = serialized_jsokey);
        DCRTPolyDeserializePublicKeyFromString(pkey, &*cxx_json);
    }
    
    pub fn get_pinned_empty_public_key(&mut self) -> cxx::UniquePtr<PublicKeyDCRTPoly> {
        return DCRTPolyGenNullPublicKey();
    }
    
    pub fn get_empty_cipher_text(&mut self) -> cxx::UniquePtr<CiphertextDCRTPoly> {
        return DCRTPolyGenNullCiphertext();
    }

    pub fn get_serialized_cipher_text(&mut self, cipher : &UniquePtr<CiphertextDCRTPoly>)  -> String{
        let serialized_json_key = DCRTPolySerializeCiphertextToString(&cipher);
        return convert_to_rust_string(serialized_json_key);
    }
    pub fn get_cipher_text_from_key(&mut self,pkey : &UniquePtr<PublicKeyDCRTPoly>, val: Option<f64>) -> UniquePtr<CiphertextDCRTPoly>{
        let mut odometer = CxxVector::<f64>::new();
        odometer.pin_mut().push(val.unwrap());
        
        let _dcrt_poly_params = ffi::DCRTPolyGenNullParams();
        let packed_text = self._cc.MakeCKKSPackedPlaintextByVectorOfDouble(&odometer, 1, 0, &_dcrt_poly_params, 0);

       return self._cc.EncryptByPublicKey(pkey, &packed_text);
    }
    
    pub fn get_deserialized_cipher_text(&self, cipher_text: Pin<&mut CiphertextDCRTPoly>, serialized_cipher : String){
        let_cxx_string!(cxx_json = serialized_cipher);
        DCRTPolyDeserializeCiphertextFromString(cipher_text, &*cxx_json);
    }

    pub fn get_plain_text_from_vector_double(&self, input: &CxxVector<f64>) -> cxx::UniquePtr<ffi::Plaintext> {
        let dcrt_poly_params = ffi::DCRTPolyGenNullParams();
        return self._cc.MakeCKKSPackedPlaintextByVectorOfDouble(input, 1, 0, &dcrt_poly_params, 0);
    }

    pub fn get_cypher_text_from_double_vector(&self,pkey : &UniquePtr<PublicKeyDCRTPoly>,
                                              input: UniquePtr<CxxVector<f64>>) ->UniquePtr<CiphertextDCRTPoly>{
        let dcrt_poly_params = ffi::DCRTPolyGenNullParams();
        let text = self._cc.MakeCKKSPackedPlaintextByVectorOfDouble(&input, 1, 0, &dcrt_poly_params, 0);

        return self._cc.EncryptByPublicKey(&pkey, &text);
    }
    
    pub fn get_cost_cipher(&self, rate_cipher : UniquePtr<CiphertextDCRTPoly>, 
                           fee_cipher: UniquePtr<CiphertextDCRTPoly>,dist_cipher: UniquePtr<CiphertextDCRTPoly>) -> UniquePtr<CiphertextDCRTPoly>{
        // calulates the cost = fee + rate * traveleddistance, values have been encrypted.
        let temp_c = self._cc.EvalMultByCiphertexts(&rate_cipher, &dist_cipher);
        return self._cc.EvalAddByCiphertexts(&fee_cipher, &temp_c);
    }
    
    pub fn get_decrypted_cost_from_result_cipher(&self, result_cipher : UniquePtr<CiphertextDCRTPoly>) -> String{
        let mut privkey= self.key_pair.as_ref().expect("unable to get pivate key").GetPrivateKey();

        let mut _result = ffi::GenNullPlainText();
        self._cc.DecryptByPrivateKeyAndCiphertext(&privkey, &result_cipher, _result.pin_mut());
        _result.SetLength(1);
        return _result.GetString();
    }

    pub fn get_serialized_eval_keys(&mut self)  -> String{
        let serialized_eval_key = DCRTPolySerializeEvalMultKeysToString(&*self._cc);
        return convert_to_rust_string(serialized_eval_key);
    }

    pub fn get_deserialized_eval_keys(&mut self, ser_eval_keys : String) {
        let_cxx_string!(cxx_json = ser_eval_keys);
        DCRTPolyDeserializeEvalMultKeysFromString(&*self._cc, &*cxx_json);
    }
    
}

