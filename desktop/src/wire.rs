//! Shared serialization rules for generated Go dashboard DTOs.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

#[derive(Clone, Default, PartialEq)]
pub struct SecretInput(Zeroizing<String>);
impl SecretInput {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}
impl Serialize for SecretInput {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.expose())
    }
}
impl<'de> Deserialize<'de> for SecretInput {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        String::deserialize(de).map(Self::new)
    }
}
pub fn null_vec<'de, T: Deserialize<'de>, D: Deserializer<'de>>(de: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(de)?.unwrap_or_default())
}
pub fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}
