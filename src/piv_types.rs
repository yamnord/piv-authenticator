use core::convert::{TryFrom, TryInto};

use flexiber::Encodable;
use serde::{Deserialize, Serialize};

/// According to spec, a PIN must be 6-8 digits, padded to 8 bytes with 0xFF.
///
/// We are more lenient, and allow ASCII 0x20..=0x7E.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pin {
    padded_pin: [u8; 8],
    len: usize,
}

impl TryFrom<&[u8]> for Pin {
    type Error = ();
    fn try_from(padded_pin: &[u8]) -> Result<Self, Self::Error> {
        let padded_pin: [u8; 8] = padded_pin.try_into().map_err(|_| ())?;
        let first_pad_byte = padded_pin[..8].iter().position(|&b| b == 0xff);
        let unpadded_pin = match first_pad_byte {
            Some(l) => &padded_pin[..l],
            None => &padded_pin,
        };
        match unpadded_pin.len() {
            len @ 6..=8 => {
                let verifier = if cfg!(feature = "strict-pin") {
                    |&byte| byte >= b'0' && byte <= b'9'
                } else {
                    |&byte| byte >= 32 && byte <= 127
                };
                if unpadded_pin.iter().all(verifier) {
                    Ok(Pin { padded_pin, len })
                } else {
                    Err(())
                }
            }
            _ => Err(())
        }
    }
}

/// A PUK may be any 8-byte binary value
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Puk(pub [u8; 8]);

impl TryFrom<&[u8]> for Puk {
    type Error = ();
    fn try_from(puk: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(puk.try_into().map_err(|_| ())?))
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// As additional reference, see:
// https://globalplatform.org/wp-content/uploads/2014/03/GPC_ISO_Framework_v1.0.pdf#page=15
//
// This GP ISO standard contains PIV types as subset (although SM is not quite clear),
// references Opacity ZKM.
pub enum Algorithm {
    // Default = 0x0, // - maps to TDES \o/
    // TwoDesEcb = 0x1,
    // TwoDesCbc = 0x2,
    Tdes = 0x3,
    // TdesCbc = 0x4,
    // early PIV contains this
    Rsa3k = 0x5,
    Rsa1k = 0x6,
    Rsa2k = 0x7,
    // meaning ECB
    Aes128 = 0x8,
    // Aes128Cbc = 0x9,
    Aes192 = 0xA,
    // Aes192Cbc = 0xB,
    Aes256 = 0xC,
    // Aes256Cbc = 0xD,
    // P224 = 0xE,
    // K233 = 0xF,
    // B233 = 0x10,
    P256 = 0x11,
    // K233 = 0x12,
    // B233 = 0x13,
    P384 = 0x14,
    // https://globalplatform.org/wp-content/uploads/2014/03/GPC_ISO_Framework_v1.0.pdf#page=15
    P521 = 0x15,

    // // non-standard! in piv-go though!
    // Ed255_prev = 0x22,

    // non-standard!
    Rsa4k = 0xE0,
    Ed255 = 0xE1,
    X255 = 0xE2,
    Ed448 = 0xE3,
    X448 = 0xE4,

    // non-standard! picked by Alex, but maybe due for removal
    P256Sha1 = 0xF0,
    P256Sha256 = 0xF1,
    P384Sha1 = 0xF2,
    P384Sha256 = 0xF3,
    P384Sha384 = 0xF4,
}

impl TryFrom<u8> for Algorithm {
    type Error = ();
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        use Algorithm::*;
        Ok(match byte {
            // 0 = "default",maps to TDES
            0x00 => Tdes,
            0x03 => Tdes,
            0x05 => Rsa3k,
            0x06 => Rsa1k,
            0x07 => Rsa2k,
            0x08 => Aes128,
            0x0A => Aes192,
            0x0c => Aes256,
            0x11 => P256,
            0x14 => P384,
            0x15 => P521,
            0xE0 => Rsa4k,
            0xE1 => X255,
            0xE2 => Ed255,
            0xE3 => X448,
            0xE4 => Ed448,
            0xF0 => P256Sha1,
            0xF1 => P256Sha256,
            0xF2 => P384Sha1,
            0xF3 => P384Sha256,
            0xF4 => P384Sha384,
            _ => return Err(()),
        })
    }
}

/// TODO:
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct CryptographicAlgorithmTemplate<'a> {
    pub algorithms: &'a [Algorithm],
}

impl Encodable for CryptographicAlgorithmTemplate<'_> {
    fn encoded_length(&self) -> flexiber::Result<flexiber::Length> {
        Ok(((3usize * (self.algorithms.len() + 1)) as u16).into())
    }

    fn encode(&self, encoder: &mut flexiber::Encoder<'_>) -> flexiber::Result<()> {
        // '80'
        let cryptographic_algorithm_identifier_tag = flexiber::Tag::context(0);
        for alg in self.algorithms.iter() {
            encoder.encode(&flexiber::TaggedSlice::from(cryptographic_algorithm_identifier_tag, &[*alg as _])?)?;
        }
        // '06'
        let object_identifier_tag = flexiber::Tag::universal(6);
        encoder.encode(&flexiber::TaggedSlice::from(object_identifier_tag, &[0x00])?)
    }
}

#[derive(Clone, Copy, Encodable, Eq, PartialEq)]
pub struct CoexistentTagAllocationAuthorityTemplate<'l> {
    #[tlv(application, primitive, number = "0xF")]  // = 0x4F
    pub application_identifier: &'l [u8],
}

impl Default for CoexistentTagAllocationAuthorityTemplate<'static> {
    fn default() -> Self {
        Self { application_identifier: crate::constants::NIST_RID }
    }
}

#[derive(Clone, Copy, Encodable, Eq, PartialEq)]
#[tlv(application, constructed, number = "0x1")]  // = 0x61
pub struct ApplicationPropertyTemplate<'l> {
    /// Application identifier of application: PIX (without RID, with version)
    #[tlv(application, primitive, number = "0xF")]  // = 0x4F
    aid: &'l[u8],

    /// Text describing the application; e.g., for use on a man-machine interface.
    #[tlv(application, primitive, number = "0x10")]  // = 0x50
    application_label: &'l [u8],

    /// Reference to the specification describing the application.
    #[tlv(application, primitive, number = "0x50")]  // = 0x5F50
    application_url: &'l [u8],

    #[tlv(context, constructed, number = "0xC")]  // = 0xAC
    supported_cryptographic_algorithms: CryptographicAlgorithmTemplate<'l>,

    #[tlv(application, constructed, number = "0x19")]  // = 0x79
    coexistent_tag_allocation_authority: CoexistentTagAllocationAuthorityTemplate<'l>,
}

impl Default for ApplicationPropertyTemplate<'static> {
    fn default() -> Self {
        Self {
            aid: &crate::constants::PIV_PIX,
            application_label: &[],
            application_url: &[],
            supported_cryptographic_algorithms: Default::default(),
            coexistent_tag_allocation_authority: Default::default(),
        }
    }
}

impl<'a> ApplicationPropertyTemplate<'a> {

    pub const fn with_application_label(self, application_label: &'a [u8]) -> Self {
        Self {
            aid: self.aid,
            application_label,
            application_url: self.application_url,
            supported_cryptographic_algorithms: self.supported_cryptographic_algorithms,
            coexistent_tag_allocation_authority: self.coexistent_tag_allocation_authority,
        }
    }

    pub const fn with_application_url(self, application_url: &'a [u8]) -> Self {
        Self {
            aid: self.aid,
            application_label: self.application_label,
            application_url,
            supported_cryptographic_algorithms: self.supported_cryptographic_algorithms,
            coexistent_tag_allocation_authority: self.coexistent_tag_allocation_authority,
        }
    }

    pub const fn with_supported_cryptographic_algorithms(self, supported_cryptographic_algorithms: &'a [Algorithm]) -> Self {
        Self {
            aid: self.aid,
            application_label: self.application_label,
            application_url: self.application_url,
            supported_cryptographic_algorithms: CryptographicAlgorithmTemplate { algorithms: supported_cryptographic_algorithms},
            coexistent_tag_allocation_authority: self.coexistent_tag_allocation_authority,
        }
    }
}


/// TODO: This should be an enum of sorts, maybe.
///
/// The data objects that appear in the dynamic authentication template (tag '7C') in the data field
/// of the GENERAL AUTHENTICATE card command depend on the authentication protocol being executed.
///
/// Note that the empty tags (i.e., tags with no data) return the same tag with content
/// (they can be seen as “requests for requests”):
/// - '80 00' Returns '80 TL <encrypted random>' (as per definition)
/// - '81 00' Returns '81 TL <random>' (as per external authenticate example)
#[derive(Clone, Copy, Default, Encodable, Eq, PartialEq)]
#[tlv(application, constructed, number = "0x1C")]  // = 0x7C
pub struct DynamicAuthenticationTemplate<'l> {
    /// The Witness (tag '80') contains encrypted data (unrevealed fact).
    /// This data is decrypted by the card.
    #[tlv(simple = "0x80")]
    witness: Option<&'l[u8]>,

    ///  The Challenge (tag '81') contains clear data (byte sequence),
    ///  which is encrypted by the card.
    #[tlv(simple = "0x81")]
    challenge: Option<&'l[u8]>,

    /// The Response (tag '82') contains either the decrypted data from tag '80'
    /// or the encrypted data from tag '81'.
    #[tlv(simple = "0x82")]
    response: Option<&'l[u8]>,

    /// Not documented in SP-800-73-4
    #[tlv(simple = "0x85")]
    exponentiation: Option<&'l[u8]>,
}

impl<'a> DynamicAuthenticationTemplate<'a> {
    pub fn with_challenge(challenge: &'a [u8]) -> Self {
        Self { challenge: Some(challenge), ..Default::default() }
    }
    pub fn with_exponentiation(exponentiation: &'a [u8]) -> Self {
        Self { exponentiation: Some(exponentiation), ..Default::default() }
    }
    pub fn with_response(response: &'a [u8]) -> Self {
        Self { response: Some(response), ..Default::default() }
    }
    pub fn with_witness(witness: &'a [u8]) -> Self {
        Self { witness: Some(witness), ..Default::default() }
    }
}

/// The Card Holder Unique Identifier (CHUID) data object is defined in accordance with the Technical
/// Implementation Guidance: Smart Card Enabled Physical Access Control Systems (TIG SCEPACS)
/// [TIG SCEPACS]. For this specification, the CHUID is common between the contact and contactless interfaces.
///
/// We remove the deprecated data elements.
// pivy: https://git.io/JfzBo
// https://www.idmanagement.gov/wp-content/uploads/sites/1171/uploads/TIG_SCEPACS_v2.3.pdf
#[derive(Clone, Copy, Encodable, Eq, PartialEq)]
#[tlv(application, primitive, number = "0x13")]  // = 0x53
pub struct CardHolderUniqueIdentifier<'l> {
    #[tlv(simple = "0x30")]
    // pivy: 26B, TIG: 25B
    fasc_n: &'l [u8],

    #[tlv(simple = "0x34")]
    // 16B type 1,2,4 UUID
    guid: [u8; 16],

    /// YYYYMMDD
    #[tlv(simple = "0x35")]
    expiration_date: [u8; 8],

    // Having this with "None" serialized as '36 00', which throws e.g. pivy-tool off.
    // This is in fact incorrect:
    // -> should be '36 10 <...>' with a 16-byte valid UUID of version 1, 4 or 5
    //
    // Need to fix in `flexiber`.
    //
    // #[tlv(simple = "0x36")]
    // // 16B, like guid
    // cardholder_uuid: Option<&'l [u8]>,

    #[tlv(simple = "0x3E")]
    issuer_asymmetric_signature: &'l [u8],

    /// The Error Detection Code is the same element as the Longitudinal Redundancy Code (LRC) in
    /// [TIG SCEPACS]. Because TIG SCEPACS makes the LRC mandatory, it is present in the CHUID.
    /// However, this document makes no use of the Error Detection Code, and therefore the length of the
    /// TLV value is set to 0 bytes (i.e., no value will be supplied).
    #[tlv(simple = "0xFE")]
    error_detection_code: [u8; 0],
}

// #[derive(Decodable, Encodable)]
// #[tlv(application, number = "0x13")]
// pub struct CardHolderUniqueIdentifier {
//     #[tlv(slice, simple = "0x30")]
//     fasc_n: [u8; 25],
//     // #[tlv(slice, simple = "0x33")]
//     // duns: [u8; 9],
//     #[tlv(slice, simple = "0x34")]
//     guid: [u8; 16],
//     #[tlv(slice, simple = "0x35")]
//     expiration_date: [u8; 8], // YYYYMMDD
//     #[tlv(slice, simple = "0x3E")]
//     issuer_asymmetric_signature: [u8; 1],
//     #[tlv(slice, simple = "0xFE")]
//     error_detection_code: [u8; 0],
// }

impl Default for CardHolderUniqueIdentifier<'static> {
    fn default() -> Self {
        Self {
            // 9999 = non-federal
            fasc_n: &[0x99, 0x99],
            guid: hex!("00000000000040008000000000000000"),
            expiration_date: *b"99991231",
            // cardholder_uuid: None,
            // at least pivy only checks for non-empty entry
            issuer_asymmetric_signature: b" ",
            error_detection_code: [0u8; 0],
        }
    }
}

impl CardHolderUniqueIdentifier<'_> {
    pub fn with_guid(self, guid: [u8; 16]) -> Self {
        let mut modified_self = self;
        modified_self.guid = guid;
        modified_self
    }
}

#[derive(Clone, Copy, Encodable, Eq, PartialEq)]
#[tlv(application, number = "0x13")]
pub struct CardCapabilityContainer {
    #[tlv(slice, simple = "0xF0")]
    card_identifier: [u8; 0],
    #[tlv(slice, simple = "0xF1")]
    capability_container_version: [u8; 0],
    #[tlv(slice, simple = "0xF2")]
    capability_container_grammar: [u8; 0],
    #[tlv(slice, simple = "0xF3")]
    application_card_url: [u8; 0],
    #[tlv(slice, simple = "0xF4")]
    pkcs_15: [u8; 0],

    #[tlv(slice, simple = "0xF5")]
    /// This is the only one that needs
    /// to be filled, namely with 0x10
    registered_data_model_number: [u8; 1],

    #[tlv(slice, simple = "0xF6")]
    access_control_rule_table: [u8; 0],
    #[tlv(slice, simple = "0xF7")]
    card_apdus: [u8; 0],
    #[tlv(slice, simple = "0xFA")]
    redirection_tag: [u8; 0],
    #[tlv(slice, simple = "0xFB")]
    capability_tuples: [u8; 0],
    #[tlv(slice, simple = "0xFC")]
    status_tuples: [u8; 0],
    #[tlv(slice, simple = "0xFD")]
    next_ccc: [u8; 0],
    #[tlv(slice, simple = "0xFE")]
    error_detection_code: [u8; 0],
}

impl Default for CardCapabilityContainer {
    fn default() -> Self {
        Self {
            card_identifier: [],
            capability_container_version: [],
            capability_container_grammar: [],
            application_card_url: [],
            pkcs_15: [],
            registered_data_model_number: [0x10],
            access_control_rule_table: [],
            card_apdus: [],
            redirection_tag: [],
            capability_tuples: [],
            status_tuples: [],
            next_ccc: [],
            error_detection_code: [],
        }
    }
}

#[derive(Clone, Copy, Encodable, Eq, PartialEq)]
#[tlv(application, number = "0x13")]
pub struct DiscoveryObject {
    #[tlv(slice, application, number = "0xF")]
    piv_card_application_aid: [u8; 11], // tag: 0x4F, max bytes = 12,
    #[tlv(slice, application, number = "0x2f")]
    pin_usage_policy: [u8; 2], // tag: 0x5F2F, max bytes = 2,
}

