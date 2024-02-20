// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::protocol::{
    SpdmBaseHashAlgo, SpdmHkdfOutputKeyingMaterial, SpdmPskHintStruct, SpdmVersion,
};

type SpdmPskHandshakeSecretHkdfExpandCbType = fn(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    psk_hint: &SpdmPskHintStruct,
    info: &[u8],
) -> Option<SpdmHkdfOutputKeyingMaterial>;
type SpdmPskMasterSecretHkdfExpandCbType = fn(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    psk_hint: &SpdmPskHintStruct,
    info: &[u8],
) -> Option<SpdmHkdfOutputKeyingMaterial>;

#[derive(Clone)]
pub struct SpdmSecretPsk {
    pub handshake_secret_hkdf_expand_cb: SpdmPskHandshakeSecretHkdfExpandCbType,

    pub master_secret_hkdf_expand_cb: SpdmPskMasterSecretHkdfExpandCbType,
}
