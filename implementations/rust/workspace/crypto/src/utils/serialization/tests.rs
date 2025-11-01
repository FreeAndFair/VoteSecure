/*
 * Serialization module tests
 *
 * @author David Ruescas (david@sequentech.io)\
 * @author Frank Zeyda (frank.zeyda@freeandfair.us)\
 * @copyright Free & Fair. 2025\
 * @version 0.1
 */

#[cfg(test)]
mod tests {
    use crate::context::Context;
    use crate::context::P256Ctx as PCtx;
    use crate::context::RistrettoCtx as RCtx;
    use crate::cryptosystem::elgamal::{Ciphertext, KeyPair};
    use crate::utils::serialization::LargeVector;
    use crate::utils::serialization::fixed::{FDeserializable, FSerializable};
    use crate::utils::serialization::variable::LENGTH_BYTES;
    use crate::utils::serialization::variable::{VDeserializable, VSerializable};
    use vser_derive::VSerializable as VSer;

    #[test]
    fn test_struct_vser_ristretto() {
        test_struct_vser::<RCtx>()
    }

    #[test]
    fn test_struct_vser_p256() {
        test_struct_vser::<PCtx>()
    }

    #[test]
    fn test_elgamal_struct_vser_ristretto() {
        test_elgamal_struct_vser::<RCtx>()
    }

    #[test]
    fn test_elgamal_struct_vser_p256() {
        test_elgamal_struct_vser::<PCtx>()
    }

    #[test]
    fn test_vector_vser_ristretto() {
        test_vector_vser::<RCtx>()
    }

    #[test]
    fn test_vector_vser_p256() {
        test_vector_vser::<PCtx>()
    }

    #[test]
    fn test_4_struct_vser_ristretto() {
        test_4_struct_vser::<RCtx>()
    }

    #[test]
    fn test_4_struct_vser_p256() {
        test_4_struct_vser::<PCtx>()
    }

    fn test_struct_vser<Ctx: Context + PartialEq>() {
        #[derive(Debug, Clone, VSer, PartialEq)]
        struct Test<Ctx: Context> {
            a: String,
            b: Ctx::Element,
            c: String,
        }

        let e1 = Ctx::random_element();
        let d = Test::<Ctx> {
            a: "hello".to_string(),
            b: e1,
            c: "world".to_string(),
        };

        let serialized = d.ser();
        let deserialized = Test::<Ctx>::deser(&serialized).unwrap();

        assert_eq!(d, deserialized);
    }

    fn test_elgamal_struct_vser<Ctx: Context>() {
        #[derive(Debug, VSer, PartialEq)]
        struct EG<Ctx: Context> {
            keypair: KeyPair<Ctx>,
            message: Ctx::Element,
            ciphertext: Ciphertext<Ctx, 1>,
        }

        let keypair = KeyPair::<Ctx>::generate();
        let message = Ctx::random_element();
        let ciphertext: Ciphertext<Ctx, 1> = keypair.encrypt(&[message.clone()]);

        let eg = EG::<Ctx> {
            keypair,
            message: message.clone(),
            ciphertext,
        };

        let serialized = eg.ser();

        let deserialized = EG::<Ctx>::deser(&serialized).unwrap();

        assert_eq!(message, deserialized.message);
        let decrypted = deserialized.keypair.decrypt(&deserialized.ciphertext);
        assert_eq!(decrypted, [message]);
    }

    fn test_vector_vser<Ctx: Context>() {
        #[derive(Debug, VSer, PartialEq)]
        struct EG<Ctx: Context> {
            keypair: KeyPair<Ctx>,
            messages: Vec<Ctx::Element>,
            ciphertexts: Vec<Ciphertext<Ctx, 1>>,
        }

        let count = 10;

        let keypair = KeyPair::<Ctx>::generate();
        let messages: Vec<Ctx::Element> = (0..count).map(|_| Ctx::random_element()).collect();

        let ciphertexts: Vec<Ciphertext<Ctx, 1>> = messages
            .iter()
            .map(|m| keypair.encrypt(&[m.clone()]))
            .collect();

        let eg = EG::<Ctx> {
            keypair,
            messages: messages.clone(),
            ciphertexts: ciphertexts,
        };

        let serialized = eg.ser();

        let deserialized = EG::<Ctx>::deser(&serialized).unwrap();

        for i in 0..count {
            assert_eq!(messages[i], deserialized.messages[i]);
            let decrypted = deserialized.keypair.decrypt(&deserialized.ciphertexts[i]);
            assert_eq!([messages[i].clone()], decrypted);
        }

        // test also that a vector with padded bytes works
        let items = vec![0u32; 10];
        let mut bytes = items.ser();
        bytes.extend_from_slice(&[0u8; 5]);
        let deserialized = Vec::<u32>::deser(&bytes).unwrap();
        assert_eq!(items, deserialized);
    }

    fn test_4_struct_vser<Ctx: Context + PartialEq>() {
        #[derive(Debug, VSer, PartialEq)]
        struct EG<Ctx: Context> {
            keypair: KeyPair<Ctx>,
            messages: Vec<[Ctx::Element; 2]>,
            ciphertexts: Vec<Ciphertext<Ctx, 2>>,
            tag: String,
        }

        let count = 5;

        let keypair = KeyPair::<Ctx>::generate();
        let messages: Vec<[Ctx::Element; 2]> = (0..count)
            .map(|_| [Ctx::random_element(), Ctx::random_element()])
            .collect();

        let ciphertexts: Vec<Ciphertext<Ctx, 2>> =
            messages.iter().map(|m| keypair.encrypt(&m)).collect();

        let tag = "test".to_string();
        let eg = EG {
            keypair,
            messages: messages.clone(),
            ciphertexts: ciphertexts,
            tag: tag.clone(),
        };

        let serialized = eg.ser();

        let back = EG::<Ctx>::deser(&serialized).unwrap();

        assert_eq!(eg, back);

        for i in 0..count {
            let decrypted = back.keypair.decrypt(&back.ciphertexts[i]);
            assert_eq!(messages[i], decrypted);
        }

        assert_eq!(tag, back.tag);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[crate::warning("Miri test fails (Stacked Borrows)")]
    fn test_elgamal_largevector_ristretto() {
        test_elgamal_largevector::<RCtx>();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[crate::warning("Miri test fails (Stacked Borrows)")]
    fn test_elgamal_largevector_p256() {
        test_elgamal_largevector::<PCtx>();
    }

    fn test_elgamal_largevector<Ctx: Context>() {
        let mut lv = LargeVector(vec![]);
        let count = 5;

        for _ in 0..count {
            let gr = [Ctx::random_element()];
            let mhr = [Ctx::random_element()];

            let ciphertext = Ciphertext::<Ctx, 1>::new(gr, mhr);
            lv.push(ciphertext);
        }

        let bytes = lv.ser();
        assert_eq!(
            bytes.len(),
            Ciphertext::<Ctx, 1>::size_bytes() * count + LENGTH_BYTES
        );
        let deserialized = LargeVector::<Ciphertext<Ctx, 1>>::deser(&bytes).unwrap();
        assert_eq!(deserialized.len(), count);
        assert!(!deserialized.is_empty());
        for i in 0..count {
            assert_eq!(lv.0[i], deserialized.0[i]);
        }
    }

    #[test]
    pub fn test_tuple_struct_ristretto() {
        test_tuple_struct_vser::<RCtx>();
    }

    #[test]
    pub fn test_tuple_struct_p256() {
        test_tuple_struct_vser::<PCtx>();
    }

    fn test_tuple_struct_vser<Ctx: Context + PartialEq>() {
        #[derive(Debug, VSer, PartialEq)]
        struct EG<Ctx: Context>(
            KeyPair<Ctx>,
            Vec<[Ctx::Element; 2]>,
            Vec<Ciphertext<Ctx, 2>>,
            String,
            u32,
            u64,
            u16,
        );

        let count = 5;

        let keypair = KeyPair::<Ctx>::generate();
        let messages: Vec<[Ctx::Element; 2]> = (0..count)
            .map(|_| [Ctx::random_element(), Ctx::random_element()])
            .collect();

        let ciphertexts: Vec<Ciphertext<Ctx, 2>> =
            messages.iter().map(|m| keypair.encrypt(&m)).collect();

        let tag = "test".to_string();
        let eg = EG(keypair, messages.clone(), ciphertexts, tag.clone(), 1, 1, 1);

        let serialized = eg.ser();

        let back = EG::<Ctx>::deser(&serialized).unwrap();

        assert_eq!(eg, back);

        for i in 0..count {
            let decrypted = back.0.decrypt(&back.2[i]);
            assert_eq!(messages[i], decrypted);
        }

        assert_eq!(tag, back.3);
    }

    #[test]
    pub fn test_tuple_struct_fser_ristretto() {
        test_tuple_struct_fser::<RCtx>();
    }

    #[test]
    pub fn test_tuple_struct_fser_p256() {
        test_tuple_struct_fser::<PCtx>();
    }

    fn test_tuple_struct_fser<Ctx: Context + PartialEq>() {
        #[derive(Debug, VSer, PartialEq)]
        struct EG<Ctx: Context>(KeyPair<Ctx>, [Ctx::Element; 2], Ciphertext<Ctx, 2>, u32);

        let keypair = KeyPair::<Ctx>::generate();
        let message: [Ctx::Element; 2] = [Ctx::random_element(), Ctx::random_element()];
        let ciphertext: Ciphertext<Ctx, 2> = keypair.encrypt(&message);

        let eg = EG(keypair, message.clone(), ciphertext, 1);

        let serialized = eg.ser_f();

        let back = EG::<Ctx>::deser_f(&serialized).unwrap();

        assert_eq!(eg, back);
        let decrypted = back.0.decrypt(&back.2);
        assert_eq!(message, decrypted);
    }
}
