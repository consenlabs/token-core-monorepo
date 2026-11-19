use crate::change_candidates::{
    bitcoin_network_id, send_authenticated_change_command, MAX_CHANGE_CANDIDATES,
};
use crate::Result;
use bitcoin::psbt::{Input, Psbt};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPubKey, KeySource};
use bitcoin::{Network, Script, TxOut};
use ikc_device::device_binding::KEY_MANAGER;
use secp256k1::{PublicKey, Secp256k1, Verification};
use std::collections::BTreeMap;

const MULTISIG_POLICY_INS: u8 = 0x55;
const NESTED_P2WSH: u8 = 1;
const NATIVE_P2WSH: u8 = 2;
const MAX_COSIGNERS: usize = 3;

/// Standard BIP48/BIP67 witness script and its verified scriptPubKey wrapper.
pub(crate) struct MultisigSpend<'a> {
    pub(crate) witness_script: &'a Script,
    pub(crate) threshold: usize,
    pub(crate) keys: Vec<PublicKey>,
    wrapper: u8,
}

impl<'a> MultisigSpend<'a> {
    pub(crate) fn from_input(input: &'a Input, script_pubkey: &Script) -> Option<Self> {
        Self::parse(
            script_pubkey,
            input.witness_script.as_ref()?,
            input.redeem_script.as_ref(),
        )
    }

    fn parse(
        script_pubkey: &Script,
        witness_script: &'a Script,
        redeem_script: Option<&Script>,
    ) -> Option<Self> {
        let witness_program = witness_script.to_v0_p2wsh();
        let wrapper = if redeem_script.is_none() && *script_pubkey == witness_program {
            NATIVE_P2WSH
        } else if redeem_script == Some(&witness_program)
            && *script_pubkey == witness_program.to_p2sh()
        {
            NESTED_P2WSH
        } else {
            return None;
        };

        let raw = witness_script.as_bytes();
        let (&threshold_op, tail) = raw.split_first()?;
        let (&checkmultisig_op, tail) = tail.split_last()?;
        let (&key_count_op, key_pushes) = tail.split_last()?;
        let threshold = threshold_op.checked_sub(0x50)? as usize;
        let count = key_count_op.checked_sub(0x50)? as usize;
        if !((2..=MAX_COSIGNERS).contains(&count)
            && (1..=count).contains(&threshold)
            && checkmultisig_op == 0xae
            && key_pushes.len() == count * 34)
        {
            return None;
        }

        let mut keys = Vec::with_capacity(count);
        for push in key_pushes.chunks_exact(34) {
            if push[0] != 33 || (push[1] != 2 && push[1] != 3) {
                return None;
            }
            let key = PublicKey::from_slice(&push[1..]).ok()?;
            // BIP67 compares the serialized compressed keys as unsigned bytes.
            if keys.last().map_or(false, |previous: &PublicKey| {
                previous.serialize() >= key.serialize()
            }) {
                return None;
            }
            keys.push(key);
        }
        Some(Self {
            witness_script,
            threshold,
            keys,
            wrapper,
        })
    }

    pub(crate) fn signing_paths(
        &self,
        input: &Input,
        network: u8,
        requested_path: &DerivationPath,
    ) -> Vec<DerivationPath> {
        self.keys
            .iter()
            .filter_map(|key| {
                let (_, path) = input.bip32_derivation.get(key)?;
                let position = BIP48Position::from_path(path, network, self.wrapper)?;
                if position
                    .account
                    .as_ref()
                    .starts_with(requested_path.as_ref())
                    || path.as_ref().starts_with(requested_path.as_ref())
                {
                    Some(path.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub(crate) fn signing_path(
        &self,
        input: &Input,
        network: u8,
        key: &PublicKey,
    ) -> Option<DerivationPath> {
        if !self.keys.contains(key) {
            return None;
        }
        let (_, path) = input.bip32_derivation.get(key)?;
        BIP48Position::from_path(path, network, self.wrapper)?;
        Some(path.clone())
    }
}

pub(crate) fn is_multisig_script_input(script: &Script, input: &Input) -> bool {
    script.is_v0_p2wsh()
        || (script.is_p2sh()
            && (input.witness_script.is_some()
                || input
                    .redeem_script
                    .as_ref()
                    .map_or(false, Script::is_v0_p2wsh)))
}

struct BIP48Position {
    account: DerivationPath,
    branch: u8,
    index: u32,
}

impl BIP48Position {
    fn from_path(path: &DerivationPath, network: u8, wrapper: u8) -> Option<Self> {
        use ChildNumber::{Hardened, Normal};
        match path.as_ref() {
            [Hardened { index: 48 }, Hardened { index: coin }, Hardened { .. }, Hardened { index: script_type }, Normal { index: branch }, Normal { index }]
                if *coin == u32::from(network)
                    && *script_type == u32::from(wrapper)
                    && *branch <= 1 =>
            {
                Some(Self {
                    account: DerivationPath::from(path.as_ref()[..4].to_vec()),
                    branch: *branch as u8,
                    index: *index,
                })
            }
            _ => None,
        }
    }
}

#[derive(PartialEq, Eq)]
struct WalletPolicy {
    wrapper: u8,
    threshold: u8,
    roots: Vec<ExtendedPubKey>,
}

impl WalletPolicy {
    fn at_spend(
        spend: &MultisigSpend<'_>,
        keys: &BTreeMap<PublicKey, KeySource>,
        xpubs: &BTreeMap<ExtendedPubKey, KeySource>,
        secp: &Secp256k1<impl Verification>,
        network: Network,
        network_id: u8,
    ) -> Option<(Self, u8, u32)> {
        if keys.len() != spend.keys.len() {
            return None;
        }
        let mut roots = Vec::with_capacity(spend.keys.len());
        let mut branch_index = None;
        for key in &spend.keys {
            let (fingerprint, path) = keys.get(key)?;
            let position = BIP48Position::from_path(path, network_id, spend.wrapper)?;
            let suffix = &path.as_ref()[4..];
            let mut matching = xpubs
                .iter()
                .filter(|(xpub, (origin_fingerprint, origin_path))| {
                    *origin_fingerprint == *fingerprint
                        && *origin_path == position.account
                        && xpub.network == network
                        && xpub.depth == 4
                        && xpub.child_number == position.account.as_ref()[3]
                        && xpub
                            .derive_pub(secp, &suffix)
                            .ok()
                            .map(|child| child.public_key)
                            == Some(*key)
                });
            let (&root, _) = matching.next()?;
            if matching.next().is_some()
                || roots
                    .iter()
                    .any(|seen: &ExtendedPubKey| seen.public_key == root.public_key)
                || branch_index.is_some() && branch_index != Some((position.branch, position.index))
            {
                return None;
            }
            roots.push(root);
            branch_index = Some((position.branch, position.index));
        }
        // Child ordering follows BIP67, independently for each script. The policy
        // compares the set of account keys using their canonical account key order.
        roots.sort_by_key(|root| root.public_key.serialize());
        let (branch, index) = branch_index?;
        Some((
            Self {
                wrapper: spend.wrapper,
                threshold: spend.threshold as u8,
                roots,
            },
            branch,
            index,
        ))
    }
}

pub(crate) struct MultisigChangePolicy {
    wallet: WalletPolicy,
    inputs: Vec<(u8, u32)>,
    outputs: Vec<(usize, u32)>,
}

impl MultisigChangePolicy {
    pub(crate) fn from_psbt(
        psbt: &Psbt,
        prevouts: &[TxOut],
        network: Network,
        network_id: u8,
    ) -> Option<Self> {
        let inputs = &psbt.inputs;
        if inputs.is_empty() || inputs.len() != prevouts.len() {
            return None;
        }
        let secp = Secp256k1::verification_only();
        let mut policy = None;
        let mut input_positions = Vec::with_capacity(inputs.len());
        for (input, prevout) in inputs.iter().zip(prevouts) {
            let spend = MultisigSpend::from_input(input, &prevout.script_pubkey)?;
            let (wallet, branch, index) = WalletPolicy::at_spend(
                &spend,
                &input.bip32_derivation,
                &psbt.xpub,
                &secp,
                network,
                network_id,
            )?;
            if policy.as_ref().map_or(false, |first| *first != wallet) {
                return None;
            }
            policy = Some(wallet);
            input_positions.push((branch, index));
        }

        let policy = policy?;
        let outputs: Vec<_> = psbt
            .unsigned_tx
            .output
            .iter()
            .zip(&psbt.outputs)
            .enumerate()
            .filter_map(|(output_index, (output, metadata))| {
                let spend = MultisigSpend::parse(
                    &output.script_pubkey,
                    metadata.witness_script.as_ref()?,
                    metadata.redeem_script.as_ref(),
                )?;
                let (wallet, branch, index) = WalletPolicy::at_spend(
                    &spend,
                    &metadata.bip32_derivation,
                    &psbt.xpub,
                    &secp,
                    network,
                    network_id,
                )?;
                (branch == 1 && policy == wallet).then_some((output_index, index))
            })
            .take(MAX_CHANGE_CANDIDATES)
            .collect();
        if outputs.is_empty() {
            return None;
        }
        Some(Self {
            wallet: policy,
            inputs: input_positions,
            outputs,
        })
    }

    pub(crate) fn send(&self, network: Network, own_account: &DerivationPath) -> Result<usize> {
        let network_id = bitcoin_network_id(network)?;
        let key_manager = KEY_MANAGER.lock();
        let host_key = &key_manager.pri_key;
        let send = |p1, p2, body: &[u8]| {
            send_authenticated_change_command(MULTISIG_POLICY_INS, p1, p2, body, host_key, true)
        };

        let mut start = vec![
            network_id,
            self.wallet.wrapper,
            self.wallet.threshold,
            self.wallet.roots.len() as u8,
        ];
        start.extend_from_slice(own_account.to_string().as_bytes());
        send(0xff, 0, &start)?;
        for (index, xpub) in self.wallet.roots.iter().enumerate() {
            let mut cosigner = xpub.public_key.serialize_uncompressed().to_vec();
            cosigner.extend_from_slice(xpub.chain_code.as_bytes());
            send(index as u8, 1, &cosigner)?;
        }
        for (index, &(branch, child)) in self.inputs.iter().enumerate() {
            let mut input = [branch, 0, 0, 0, 0];
            input[1..].copy_from_slice(&child.to_be_bytes());
            send(index as u8, 2, &input)?;
        }
        for &(index, child) in &self.outputs {
            send(index as u8, 3, &child.to_be_bytes())?;
        }
        send(0xff, 0x80, &[0])?;
        Ok(self.outputs.len())
    }
}
