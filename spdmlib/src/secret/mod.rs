// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
mod secret_callback;

use conquer_once::spin::OnceCell;
pub use secret_callback::SpdmSecretPsk;

static SECRET_PSK_INSTANCE: OnceCell<SpdmSecretPsk> = OnceCell::uninit();

pub mod measurement {
    use crate::protocol::*;

    pub trait MeasurementProvider {
        /*
            Function to get measurements.

            This function wraps SpdmSecret.measurement_collection_cb callback
            Device security lib is responsible for the implementation of SpdmSecret.
            If SECRET_INSTANCE got no registered, a panic with string "not implemented"
            will be emit.

            @When measurement_index == SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber
                    A dummy Some(SpdmMeasurementRecordStructure) is returned, with its number_of_blocks
                    field set and all other field reserved.
            @When measurement_index != SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber
                    A normal Some(SpdmMeasurementRecordStructure) is returned, with all fields valid.
        */
        fn measurement_collection(
            &self,
            spdm_version: SpdmVersion,
            measurement_specification: SpdmMeasurementSpecification,
            measurement_hash_algo: SpdmMeasurementHashAlgo,
            measurement_index: usize,
        ) -> Option<SpdmMeasurementRecordStructure>;

        fn generate_measurement_summary_hash(
            &self,
            spdm_version: SpdmVersion,
            base_hash_algo: SpdmBaseHashAlgo,
            measurement_specification: SpdmMeasurementSpecification,
            measurement_hash_algo: SpdmMeasurementHashAlgo,
            measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        ) -> Option<SpdmDigestStruct>;
    }

    pub struct DefaultMeasurementProvider {}

    impl MeasurementProvider for DefaultMeasurementProvider {
        fn measurement_collection(
            &self,
            _spdm_version: SpdmVersion,
            _measurement_specification: SpdmMeasurementSpecification,
            _measurement_hash_algo: SpdmMeasurementHashAlgo,
            _measurement_index: usize,
        ) -> Option<SpdmMeasurementRecordStructure> {
            unimplemented!()
        }

        fn generate_measurement_summary_hash(
            &self,
            _spdm_version: SpdmVersion,
            _base_hash_algo: SpdmBaseHashAlgo,
            _measurement_specification: SpdmMeasurementSpecification,
            _measurement_hash_algo: SpdmMeasurementHashAlgo,
            _measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        ) -> Option<SpdmDigestStruct> {
            unimplemented!()
        }
    }
}
pub mod psk {
    use super::{SpdmSecretPsk, SECRET_PSK_INSTANCE};
    use crate::protocol::*;
    pub fn register(context: SpdmSecretPsk) -> bool {
        SECRET_PSK_INSTANCE.try_init_once(|| context).is_ok()
    }

    static UNIMPLETEMTED: SpdmSecretPsk = SpdmSecretPsk {
        handshake_secret_hkdf_expand_cb: |_spdm_version: SpdmVersion,
                                          _base_hash_algo: SpdmBaseHashAlgo,
                                          _psk_hint: &SpdmPskHintStruct,
                                          _info: &[u8]|
         -> Option<SpdmHkdfOutputKeyingMaterial> {
            unimplemented!()
        },

        master_secret_hkdf_expand_cb: |_spdm_version: SpdmVersion,
                                       _base_hash_algo: SpdmBaseHashAlgo,
                                       _psk_hint: &SpdmPskHintStruct,
                                       _info: &[u8]|
         -> Option<SpdmHkdfOutputKeyingMaterial> {
            unimplemented!()
        },
    };

    pub fn handshake_secret_hkdf_expand(
        spdm_version: SpdmVersion,
        base_hash_algo: SpdmBaseHashAlgo,
        psk_hint: &SpdmPskHintStruct,
        info: &[u8],
    ) -> Option<SpdmHkdfOutputKeyingMaterial> {
        (SECRET_PSK_INSTANCE
            .try_get_or_init(|| UNIMPLETEMTED.clone())
            .ok()?
            .handshake_secret_hkdf_expand_cb)(spdm_version, base_hash_algo, psk_hint, info)
    }

    pub fn master_secret_hkdf_expand(
        spdm_version: SpdmVersion,
        base_hash_algo: SpdmBaseHashAlgo,
        psk_hint: &SpdmPskHintStruct,
        info: &[u8],
    ) -> Option<SpdmHkdfOutputKeyingMaterial> {
        (SECRET_PSK_INSTANCE
            .try_get_or_init(|| UNIMPLETEMTED.clone())
            .ok()?
            .master_secret_hkdf_expand_cb)(spdm_version, base_hash_algo, psk_hint, info)
    }
}

pub mod asym_sign {
    use crate::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct};

    pub trait SecretAsymSigner {
        /// Get supported hash algo and aysm algo for this SecretAsymSigner. This method
        /// can be used to determine the RequesterContext's req_asym_algo and
        /// ResponderContext's base_asym_algo filed
        fn supported_algo(&self) -> (SpdmBaseHashAlgo, SpdmBaseAsymAlgo);

        fn sign(
            &self,
            base_hash_algo: SpdmBaseHashAlgo,
            base_asym_algo: SpdmBaseAsymAlgo,
            data: &[u8],
        ) -> Option<SpdmSignatureStruct>;
    }

    pub struct DefaultSecretAsymSigner {}

    impl SecretAsymSigner for DefaultSecretAsymSigner {
        fn supported_algo(&self) -> (SpdmBaseHashAlgo, SpdmBaseAsymAlgo) {
            /* Support none asym algo */
            (SpdmBaseHashAlgo::all(), SpdmBaseAsymAlgo::empty())
        }

        fn sign(
            &self,
            _base_hash_algo: SpdmBaseHashAlgo,
            _base_asym_algo: SpdmBaseAsymAlgo,
            _data: &[u8],
        ) -> Option<SpdmSignatureStruct> {
            unimplemented!()
        }
    }
}
