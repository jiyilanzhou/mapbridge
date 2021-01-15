// This file is part of Substrate.

// Copyright (C) 2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Merkle Mountain Range
//!
//! ## Overview
//!
//! Details on Merkle Mountain Ranges (MMRs) can be found here:
//! <https://github.com/mimblewimble/grin/blob/master/doc/mmr.md>
//!
//! The MMR pallet constructs a MMR from leaf data obtained on every block from
//! `LeafDataProvider`. MMR nodes are stored both in:
//! - on-chain storage - hashes only; not full leaf content)
//! - off-chain storage - via Indexing API we push full leaf content (and all internal nodes as
//! well) to the Off-chain DB, so that the data is available for Off-chain workers.
//! Hashing used for MMR is configurable independently from the rest of the runtime (i.e. not using
//! `frame_system::Hashing`) so something compatible with external chains can be used (like
//! Keccak256 for Ethereum compatibility).
//!
//! Depending on the usage context (off-chain vs on-chain) the pallet is able to:
//! - verify MMR leaf proofs (on-chain)
//! - generate leaf proofs (off-chain)
//!
//! See [map_mmr_primitive::Compact] documentation for how you can optimize proof size for leafs that are
//! composed from multiple elements.
//!
//! ## What for?
//!
//!	Primary use case for this pallet is to generate MMR root hashes, that can latter on be used by
//!	BEEFY protocol (see <https://github.com/paritytech/grandpa-bridge-gadget>).
//!	MMR root hashes along with BEEFY will make it possible to build Super Light Clients (SLC) of
//!	Substrate-based chains. The SLC will be able to follow finality and can be shown proofs of more
//!	details that happened on the source chain.
//!	In that case the chain which contains the pallet generates the Root Hashes and Proofs, which
//!	are then presented to another chain acting as a light client which can verify them.
//!
//!	Secondary use case is to archive historical data, but still be able to retrieve them on-demand
//!	if needed. For instance if parent block hashes are stored in the MMR it's possible at any point
//!	in time to provide a MMR proof about some past block hash, while this data can be safely pruned
//!	from on-chain storage.
//!
//! NOTE This pallet is experimental and not proven to work in production.
//!
#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Encode, Decode};
use frame_support::{
	decl_module, decl_storage,debug,
	weights::Weight,
};
use sp_runtime::{
	traits::{self},
	RuntimeDebug,
};
use map_mmr_primitive::{
	Proof, OnNewRoot};
use map_mmr_primitive::LeafDataProvider;
use map_mmr_rpc_runtime_api::{RuntimeDispatchInfo};

#[cfg(not(feature = "std"))]
use sp_std::{vec};

mod default_weights;
mod mmr;
#[cfg(any(feature = "runtime-benchmarks", test))]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub trait WeightInfo {
	fn on_initialize(peaks: u64) -> Weight;
}

#[cfg(feature = "std")]
use serde::Serialize;

pub const MAP_MMR_ROOT_LOG_ID: [u8; 6] = *b"MMROOT";

#[cfg_attr(feature = "std", derive(Serialize))]
#[derive(Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug)]
pub struct MapMMRRootLog<Hash> {
	/// Specific prefix to identify the mmr root log in the digest items with Other type.
	pub prefix: [u8; 6],
	/// The merkle mountain range root hash.
	pub mmr_root: Hash,
}

/// This pallet's Traituration trait
pub trait Trait<I = DefaultInstance>: frame_system::Trait {
	/// Prefix for elements stored in the Off-chain DB via Indexing API.
	///
	/// Each node of the MMR is inserted both on-chain and off-chain via Indexing API.
	/// The former does not store full leaf content, just it's compact version (hash),
	/// and some of the inner mmr nodes might be pruned from on-chain storage.
	/// The later will contain all the entries in their full form.
	///
	/// Each node is stored in the Off-chain DB under key derived from the [`Self::INDEXING_PREFIX`] and
	/// it's in-tree index (MMR position).
	const INDEXING_PREFIX: &'static [u8];

	/// A hasher type for MMR.
	///
	/// To construct trie nodes that result in merging (bagging) two peaks, depending on the node
	/// kind we take either:
	/// - The node (hash) itself if it's an inner node.
	/// - The hash of SCALE-encoding of the leaf data if it's a leaf node.
	///
	/// Then we create a tuple of these two hashes, SCALE-encode it (concatenate) and
	/// hash, to obtain a new MMR inner node - the new peak.
	type Hashing: traits::Hash<Output = <Self as frame_system::Trait>::Hash>;

	/// Data stored in the leaf nodes.
	///
	/// The [LeafData](map_mmr_primitive::LeafDataProvider) is responsible for returning the entire leaf
	/// data that will be inserted to the MMR.
	/// [LeafDataProvider](map_mmr_primitive::LeafDataProvider)s can be composed into tuples to put
	/// multiple elements into the tree. In such a case it might be worth using [map_mmr_primitive::Compact]
	/// to make MMR proof for one element of the tuple leaner.
	type LeafData: LeafDataProvider;

	/// A hook to act on the new MMR root.
	///
	/// For some applications it might be beneficial to make the MMR root available externally
	/// apart from having it in the storage. For instance you might output it in the header digest
	/// (see [frame_system::Module::deposit_log]) to make it available for Light Clients.
	/// Hook complexity should be `O(1)`.
	type OnNewRoot: OnNewRoot<<Self as frame_system::Trait>::Hash>;

	/// Weights for this pallet.
	type WeightInfo: WeightInfo;
}

decl_storage! {
	trait Store for Module<T: Trait<I>, I: Instance = DefaultInstance> as MerkleMountainRange {
		/// Latest MMR Root hash.
		pub RootHash get(fn mmr_root_hash): T::Hash;

		/// Current size of the MMR (number of leaves).
		pub NumberOfLeaves get(fn mmr_leaves): u64;

		/// Hashes of the nodes in the MMR.
		///
		/// Note this collection only contains MMR peaks, the inner nodes (and leaves)
		/// are pruned and only stored in the Offchain DB.
		pub Nodes get(fn mmr_peak): map hasher(identity) u64 => Option<T::Hash>;
	}
}

decl_module! {
	/// A public part of the pallet.
	pub struct Module<T: Trait<I>, I: Instance = DefaultInstance> for enum Call where origin: T::Origin {
		fn on_initialize(n: T::BlockNumber) -> Weight {
			Self::append_block(n)
		}
	}
}

/// A MMR specific to the pallet.
type ModuleMmr<StorageType, T, I> = mmr::Mmr<StorageType, T, I, LeafOf<T, I>>;

/// Leaf data.
type LeafOf<T, I> = <<T as Trait<I>>::LeafData as LeafDataProvider>::LeafData;

/// Hashing used for the pallet.
pub(crate) type HashingOf<T, I> = <T as Trait<I>>::Hashing;

impl<T: Trait<I>, I: Instance> Module<T, I> {
	impl_rpc! {
		pub fn gen_proof_rpc(
			leaf_index: u64,
		) -> RuntimeDispatchInfo<T::Hash> {

				let mmr: ModuleMmr<mmr::storage::OffchainStorage, T, I> = mmr::Mmr::new(Self::mmr_leaves());
					if let Ok(merkle_proof) = mmr.generate_proof(leaf_index) {
						return RuntimeDispatchInfo {
							mmr_size: mmr::utils::NodesUtils::new(Self::mmr_leaves()).size(),
							proof: merkle_proof.1,
						};
					}

			RuntimeDispatchInfo {
				mmr_size: 0,
				proof: Proof{
							leaf_index: 0,
							leaf_count: 7,
							items: vec![]
						},
			}
		}
	}


	fn offchain_key(pos: u64) -> sp_std::prelude::Vec<u8> {
		(T::INDEXING_PREFIX, pos).encode()
	}

    /// Append the current block as leaf node into MMR
    fn append_block(_n: T::BlockNumber) -> Weight {
        let leaves = Self::mmr_leaves();
        let peaks_before = mmr::utils::NodesUtils::new(leaves).number_of_peaks();
        let data = T::LeafData::leaf_data();
        // append new leaf to MMR
        let mut mmr: ModuleMmr<mmr::storage::RuntimeStorage, T, I> = mmr::Mmr::new(leaves);
        mmr.push(data.clone()).expect("MMR push never fails.");

        // update the size
        let (leaves, root) = mmr.finalize().expect("MMR finalize never fails.");
        <T::OnNewRoot as OnNewRoot<_>>::on_new_root(&root);

		debug::native::info!("append_block! {:?} {} {} {:?}",data, _n,leaves, root);

		<NumberOfLeaves>::put(leaves);
        <RootHash<T, I>>::put(root);

        let peaks_after = mmr::utils::NodesUtils::new(leaves).number_of_peaks();
        T::WeightInfo::on_initialize(peaks_before.max(peaks_after))
    }

	pub fn retrieve_mmr(leaf: u64) -> Result<(u64, T::Hash), mmr::Error> {
		let mmr: ModuleMmr<mmr::storage::RuntimeStorage, T, I> = mmr::Mmr::new(leaf+1);
        mmr.finalize()
	}
	/// Generate a MMR proof for the given `leaf_index`.
	///
	/// Note this method can only be used from an off-chain context
	/// (Offchain Worker or Runtime API call), since it requires
	/// all the leaves to be present.
	/// It may return an error or panic if used incorrectly.
	pub fn generate_proof(block_number: u64) -> Result<
		(LeafOf<T, I>, Proof<T::Hash>),
		mmr::Error,
	> {
		let mmr: ModuleMmr<mmr::storage::OffchainStorage, T, I> = mmr::Mmr::new(Self::mmr_leaves());
		let result = mmr.generate_proof(block_number -1);
		result
	}

	/// Verify MMR proof for given `leaf`.
	///
	/// This method is safe to use within the runtime code.
	/// It will return `Ok(())` if the proof is valid
	/// and an `Err(..)` if MMR is inconsistent (some leaves are missing)
	/// or the proof is invalid.
	pub fn verify_proof_by_root(
		leaf: LeafOf<T, I>,
		proof: Proof<T::Hash>,
	) -> Result<(), mmr::Error> {
		if proof.leaf_count > Self::mmr_leaves()
			|| proof.leaf_count == 0
			|| proof.items.len() as u32 > mmr::utils::NodesUtils::new(proof.leaf_count).depth()
		{
			return Err(mmr::Error::Verify.log_debug(
				"The proof has incorrect number of leaves or proof items."
			));
		}

		let mmr: ModuleMmr<mmr::storage::RuntimeStorage, T, I> = mmr::Mmr::new(proof.leaf_count);
		let is_valid = mmr.verify_leaf_proof(leaf, proof)?;
		if is_valid {
			Ok(())
		} else {
			Err(mmr::Error::Verify.log_debug("The proof is incorrect."))
		}
	}
}

#[macro_export]
macro_rules! impl_rpc {
	(
		$(pub)? fn $fnname:ident($($params:tt)*) -> $respname:ident$(<$($gtype:ty),+>)? {
			$($fnbody:tt)*
		}
	) => {
		#[cfg(feature = "std")]
		pub fn $fnname($($params)*) -> $respname$(<$($gtype),+>)?
		$(
		where
			$($gtype: std::fmt::Display + std::str::FromStr),+
		)?
		{
			$($fnbody)*
		}

		#[cfg(not(feature = "std"))]
		pub fn $fnname($($params)*) -> $respname$(<$($gtype),+>)? {
			$($fnbody)*
		}
	};
}
