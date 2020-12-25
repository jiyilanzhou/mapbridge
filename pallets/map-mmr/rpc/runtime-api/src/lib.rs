//! Runtime API definition required by map-mmr RPC extensions.
//!
//! This API should be imported and implemented by the runtime,
//! of a node that wants to use the custom RPC extension
//! adding map-mmr access methods.

#![cfg_attr(not(feature = "std"), no_std)]

// --- crates ---
use codec::{Codec, Decode, Encode};
use sp_api::decl_runtime_apis;
use sp_runtime::traits::{MaybeDisplay, MaybeFromStr};
use sp_std::prelude::*;
use map_mmr_primitive::{Proof};

impl_runtime_dispatch_info! {
	struct RuntimeDispatchInfo<Hash> {
		mmr_size: u64,
		proof: Proof<Hash>
	}

	fn custom_serializer() -> closure {
		|t| {
			let s = format!("{:?}", t);
			if s.len() > 6 {
				(&s[6..s.len() - 1]).to_owned()
			} else {
				s
			}
		}
	}
}

decl_runtime_apis! {
	pub trait MAPMMRApi<Hash>
	where
		Hash: core::fmt::Debug + Codec + MaybeDisplay + MaybeFromStr,
	{
		fn gen_proof(
			leaf_index: u64,
		) -> RuntimeDispatchInfo<Hash>;
	}
}

#[macro_export]
macro_rules! impl_runtime_dispatch_info {
	(
		$(pub)? struct $sname:ident$(<$($gtype:ident),+>)? {
			$($(pub)? $fname:ident: $ftype:ty),+
		}

		fn custom_serializer() -> closure {
			$($custom_serializer:tt)*
		}
	) => {
		#[cfg(feature = "std")]
		use serde::{Serialize, Serializer};

		#[cfg(not(feature = "std"))]
		#[derive(Debug, Default, Eq, PartialEq, Encode, Decode)]
		pub struct $sname$(<$($gtype),+>)?
		$(
		where
			$($gtype: core::fmt::Debug),+
		)?
		{
			$(
				pub $fname: $ftype
			),+
		}

		#[cfg(feature = "std")]
		#[derive(Debug, Default, Eq, PartialEq, Encode, Decode, Serialize)]
		#[serde(rename_all = "camelCase")]
		pub struct $sname$(<$($gtype),+>)?
		$(
		where
			$($gtype: core::fmt::Debug),+
		)?
		{
			$(
				#[serde(serialize_with = "serialize_as_string")]
				#[serde(deserialize_with = "deserialize_from_string")]
				pub $fname: $ftype
			),+
		}

		#[cfg(feature = "std")]
		fn serialize_as_string<S: Serializer, T: std::fmt::Debug>(
			t: &T,
			serializer: S,
		) -> Result<S::Ok, S::Error> {
			serializer.serialize_str(&($($custom_serializer)*)(t))
		}
	};
	(
		$(pub)? struct $sname:ident$(<$($gtype:ident),+>)? {
			$($(pub)? $fname:ident: $ftype:ty),+
		}
	) => {
		#[cfg(feature = "std")]
		use serde::{Serialize, Serializer};

		#[cfg(not(feature = "std"))]
		#[derive(Default, Eq, PartialEq, Encode, Decode)]
		pub struct $sname$(<$($gtype),+>)? {
			$(
				pub $fname: $ftype
			),+
		}

		#[cfg(feature = "std")]
		#[derive(Debug, Default, Eq, PartialEq, Encode, Decode, Serialize)]
		#[serde(rename_all = "camelCase")]
		pub struct $sname$(<$($gtype),+>)?
		$(
		where
			$($gtype: std::fmt::Display),+
		)?
		{
			$(
				#[serde(serialize_with = "serialize_as_string")]
				pub $fname: $ftype
			),+
		}

		#[cfg(feature = "std")]
		fn serialize_as_string<S: Serializer, T: std::fmt::Display>(
			t: &T,
			serializer: S,
		) -> Result<S::Ok, S::Error> {
			serializer.serialize_str(&t.to_string())
		}
	};
}
