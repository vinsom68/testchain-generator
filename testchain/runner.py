import atexit
import json
import logging
import os
import shutil
import subprocess
import tempfile
import struct
import binascii
from time import sleep
from typing import List, Type

import bitcoin
import bitcoin.rpc
from bitcoin.core import b2lx
from bitcoin.core.key import use_libsecp256k1_for_signing
from testchain.generator import Generator
from testchain.address import COINBASE_KEY, COINBASE_ADDRESS

LOG_LEVEL = logging.INFO
bitcoin.SelectParams('regtest')

use_libsecp256k1_for_signing(True)  # for deterministic coinbase transactions and signatures

REGTEST_MAGIC = b"\xfa\xbf\xb5\xda"


class Runner(object):
    motif_generators: List[Generator]

    def __init__(self, output_dir, chain, exec):
        self.chain = chain
        self.exec = exec
        self.current_time = 1535760000
        self.prev_block = None
        self.motif_generators = []
        self.kv = {}
        self.output_dir = os.path.join(output_dir, '')
        self._setup_logger()
        self._setup_bitcoind()
        self.proxy = bitcoin.rpc.Proxy(btc_conf_file=self._conf_file())
        self.wallet_proxy = None
        self._import_coinbase_key()
        self._assert_regtest_chain()
        # Mine after import so wallet owns the coinbase outputs
        self.proxy.call("generatetoaddress", 101, COINBASE_ADDRESS)
        self._ensure_spendable_funds()

    def _ensure_spendable_funds(self):
        """Mine enough blocks so coinbase outputs are spendable."""
        try:
            height = self.proxy.getblockcount()
        except Exception:
            height = 0
        if height < 101:
            blocks_needed = 101 - height
            self.proxy.call("generatetoaddress", blocks_needed, COINBASE_ADDRESS)
        # Verify wallet sees coinbase outputs
        try:
            unspents = self.proxy.listunspent(minconf=1, addrs=[COINBASE_ADDRESS])
        except Exception:
            unspents = []
        if not unspents:
            try:
                info = self.proxy.call("getaddressinfo", COINBASE_ADDRESS)
                self.log.info("Coinbase address info: ismine=%s, iswatchonly=%s",
                              info.get("ismine"), info.get("iswatchonly"))
            except Exception:
                pass
            try:
                all_unspents = self.proxy.listunspent(minconf=1)
                self.log.info("Wallet unspents (all): %d", len(all_unspents))
            except Exception:
                pass

    def _import_coinbase_key(self):
        """
        Import the coinbase key into the wallet. Prefer legacy importprivkey,
        but fall back to importdescriptors when importprivkey is unavailable.
        """
        try:
            # Prefer legacy wallets when supported
            self._ensure_wallet(descriptors=False)
            (self.wallet_proxy or self.proxy).call("importprivkey", COINBASE_KEY)
            return
        except bitcoin.rpc.JSONRPCError as err:
            msg = getattr(err, "error", {}).get("message", "")
            if "Method not found" not in msg and "No wallet is loaded" not in msg \
               and "descriptors argument must be set to \"true\"" not in msg:
                raise

        # Fall back to descriptor wallet + importdescriptors
        self._ensure_wallet(descriptors=True)
        desc = "pkh({})".format(COINBASE_KEY)
        info = (self.wallet_proxy or self.proxy).call("getdescriptorinfo", desc)
        desc_with_checksum = "{}#{}".format(desc, info["checksum"])
        res = (self.wallet_proxy or self.proxy).call("importdescriptors", [{
            "desc": desc_with_checksum,
            "timestamp": 0,
            "active": False,
            "label": "coinbase"
        }])
        if not res or not res[0].get("success", False):
            self.log.info("importdescriptors result: %s", res)
            raise RuntimeError("importdescriptors failed")
        try:
            addr_info = (self.wallet_proxy or self.proxy).call("getaddressinfo", COINBASE_ADDRESS)
            self.log.info("Post-import address info: ismine=%s, iswatchonly=%s",
                          addr_info.get("ismine"), addr_info.get("iswatchonly"))
        except Exception:
            pass

    def _ensure_wallet(self, descriptors):
        try:
            self.proxy.call("createwallet", "testchain", False, False, "", False, bool(descriptors))
            self._use_wallet_proxy("testchain")
        except bitcoin.rpc.JSONRPCError as err:
            msg = getattr(err, "error", {}).get("message", "")
            if "already exists" in msg or "exists" in msg:
                self._use_wallet_proxy("testchain")
                return
            # If legacy wallets are disabled, allow fallback to descriptors
            if not descriptors and ("descriptors=false" in msg or "descriptors argument must be set to \"true\"" in msg):
                return
            # If createwallet isn't supported, let caller decide
            if "Method not found" in msg:
                return
            raise

    def _use_wallet_proxy(self, wallet_name):
        """Switch to wallet-scoped RPC endpoint for wallet methods."""
        self.wallet_proxy = bitcoin.rpc.Proxy(service_url=self._wallet_url(wallet_name))
        self.proxy = self.wallet_proxy

    def _wallet_url(self, wallet_name):
        # Read RPC settings from the generated bitcoin.conf
        conf = {"rpcuser": "", "rpcpassword": ""}
        try:
            with open(self._conf_file(), "r") as fd:
                for line in fd.readlines():
                    if "#" in line:
                        line = line[:line.index("#")]
                    if "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    conf[k.strip()] = v.strip()
        except FileNotFoundError:
            pass
        host = conf.get("rpcconnect", "localhost")
        port = conf.get("rpcport", "18443")
        user = conf.get("rpcuser", "")
        password = conf.get("rpcpassword", "")
        return "http://{}:{}@{}:{}/wallet/{}".format(user, password, host, port, wallet_name)

    def _setup_logger(self):
        self.log = logging.getLogger(__name__)
        self.log.setLevel(LOG_LEVEL)
        ch = logging.StreamHandler()
        ch.setLevel(LOG_LEVEL)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.log.addHandler(ch)

    def _setup_bitcoind(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.log.info("bitcoind datadir: {}".format(self.tempdir.name))

        # copy conf file to temp dir
        conf_src = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "bitcoin.conf")
        conf_src = os.path.realpath(conf_src)
        shutil.copy(conf_src, self.tempdir.name)

        # launch bitcoind
        conf_path = self._conf_file()
        params = [
            self.exec,
            "-rpcport=18443",
            "-datadir={}".format(self.tempdir.name),
            "-conf={}".format(conf_path),
            "-mocktime={}".format(self.current_time),
            "-regtest",
        ]
        # Relax policy for regtest synthetic chain generation (dust/zero-fee)
        params += ["-minrelaytxfee=0", "-dustrelayfee=0", "-acceptnonstdtxn=1"]

        # Disable Bitcoin Cash specific address format (breaks Python library)
        # Enable CTOR
        if self.chain == "bch":
            params += ["-usecashaddr=0", "-magneticanomalyactivationtime=0"]
        self.proc = subprocess.Popen(params, stdout=subprocess.DEVNULL)

        # kill process when generator is done
        atexit.register(self._terminate)

        self.log.info("Waiting 10 seconds for bitcoind to start")
        sleep(10)

    def _conf_file(self):
        return "{}/bitcoin.conf".format(self.tempdir.name)

    def _terminate(self):
        """
        Kills the bitcoind process
        """
        self.proc.terminate()
        self.log.info("Waiting 5 seconds for bitcoind to quit")
        sleep(5)

    def _shutdown_bitcoind(self):
        """
        Gracefully stop bitcoind and wait for it to flush block files.
        """
        try:
            self.proxy.call("stop")
        except Exception:
            # If RPC is already down, just fall through to wait/terminate.
            self.log.warning("bitcoind stop RPC failed; attempting to wait/terminate")
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.log.warning("bitcoind did not exit in time; terminating")
            self.proc.terminate()
            self.proc.wait(timeout=10)

    def _assert_regtest_chain(self):
        info = self.proxy.call("getblockchaininfo")
        chain = info.get("chain")
        self.log.info("bitcoind chain: {}".format(chain))
        if chain != "regtest":
            raise RuntimeError("bitcoind is not running regtest (chain={})".format(chain))

    def next_timestamp(self):
        self.current_time += 600
        return self.current_time

    def export_address_counts(self):
        self._address_sanity_check()
        counts = {"p2pkh": 2, "p2wpkh": 0, "p2sh": 0, "p2wsh": 0}  # coinbase addresses
        for g in self.motif_generators:
            for addr in g.addresses:
                counts[addr.type] += 1
        self.kv["p2pkh_address_count"] = counts["p2pkh"]
        self.kv["p2wpkh_address_count"] = counts["p2wpkh"]
        self.kv["p2sh_address_count"] = counts["p2sh"]
        self.kv["p2wsh_address_count"] = counts["p2wsh"]

    def _address_sanity_check(self):
        total_addresses = 0
        unique_addresses = set()
        for g in self.motif_generators:
            key_indizes = [x.key_index for x in g.addresses]
            unique_addresses |= set(key_indizes)
            total_addresses += len(key_indizes)
        if len(unique_addresses) != total_addresses:
            self.log.warning("Addresses are not unique.")

    def _write_blk_from_rpc(self, dest_path):
        """
        Rebuild blk00000.dat from RPC to avoid relying on bitcoind's on-disk format.
        """
        height = self.proxy.getblockcount()
        self.log.info("Writing blk00000.dat from RPC (height=%s)", height)
        with open(dest_path, "wb") as dest:
            for h in range(height + 1):
                block_hash = self.proxy.getblockhash(h)
                raw_hex = self.proxy.call("getblock", b2lx(block_hash), 0)
                raw = bytes.fromhex(raw_hex)
                dest.write(REGTEST_MAGIC)
                dest.write(struct.pack("<I", len(raw)))
                dest.write(raw)

    def copy_blk_file(self, truncate_file=True, use_rpc=False):
        """
        Copies the first blk file from the regtest directory to the output directory
        :param truncate_file: Whether the final block file should be truncated. Works with BlockSci, but may not work
        when using other parsers.
        :param use_rpc: Whether to rebuild blk00000.dat from RPC instead of copying bitcoind output.
        """
        blk_destination = self.output_dir + self.chain + "/regtest/blocks/"
        self.log.info("Copying blk00000.dat to {}".format(blk_destination))
        if not os.path.exists(blk_destination):
            os.makedirs(blk_destination)
        dest_path = blk_destination + "blk00000.dat"
        if use_rpc:
            self._write_blk_from_rpc(dest_path)
            return
        source = "{}/regtest/blocks/blk00000.dat".format(self.tempdir.name)
        with open(source, "rb") as f:
            source_magic = f.read(4)
        if source_magic != REGTEST_MAGIC:
            self.log.warning(
                "Non-standard regtest magic in source blk00000.dat: %s (expected %s)",
                binascii.hexlify(source_magic).decode("ascii"),
                binascii.hexlify(REGTEST_MAGIC).decode("ascii"),
            )

        if truncate_file:
            with open(source, "rb") as f:
                with open(blk_destination + "blk00000.dat", "wb") as dest:
                    counter = 0
                    while True:
                        bts = f.read(16)
                        if not bts or counter == 16:
                            break
                        if bts == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                            counter += 1
                        else:
                            counter = 0
                        dest.write(bts)
        else:
            shutil.copy(source, blk_destination)

        # Log the magic actually written to output
        blk_path = blk_destination + "blk00000.dat"
        with open(blk_path, "rb") as f:
            magic = f.read(4)
        if magic != REGTEST_MAGIC:
            self.log.warning(
                "Non-standard regtest magic in %s: %s (expected %s)",
                blk_path,
                binascii.hexlify(magic).decode("ascii"),
                binascii.hexlify(REGTEST_MAGIC).decode("ascii"),
            )

    def persist_hashes(self):
        """
        Dumps hashes into JSON file.
        """
        # kv = {}
        # for g in self.motif_generators:
        #     kv = {**kv, **g.stored_hashes}

        self.log.info("Writing hashes to file output.json")
        self.log.debug(self.kv)
        dest_dir = self.output_dir + self.chain + "/"
        if not os.path.exists(dest_dir):
            os.mkdir(dest_dir)
        with open(dest_dir + "output.json", "w") as f:
            json.dump(self.kv, f, indent=4)

    def add_generator(self, generator: Type[Generator]):
        gen = generator(self.proxy, self.chain, self.log, self.kv, (len(self.motif_generators) + 1) * 10000,
                        self.next_timestamp)
        self.log.debug("Magic No: {}".format(gen.offset))
        self.motif_generators.append(gen)

    def run(self):
        for g in self.motif_generators:
            g.run()
        self._address_sanity_check()
        self.copy_blk_file(truncate_file=False, use_rpc=True)
        self._shutdown_bitcoind()
        self.persist_hashes()
