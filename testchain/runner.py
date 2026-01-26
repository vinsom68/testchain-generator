import atexit
import json
import logging
import os
import shutil
import subprocess
import tempfile
from time import sleep
from typing import List, Type

import bitcoin
import bitcoin.rpc
from bitcoin.core.key import use_libsecp256k1_for_signing
from testchain.generator import Generator
from testchain.address import COINBASE_KEY, COINBASE_ADDRESS

LOG_LEVEL = logging.INFO
bitcoin.SelectParams('regtest')

use_libsecp256k1_for_signing(True)  # for deterministic coinbase transactions and signatures


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
        shutil.copy("bitcoin.conf", self.tempdir.name)

        # launch bitcoind
        params = [self.exec, "-rpcport=18443", "-datadir={}".format(self.tempdir.name),
                  "-mocktime={}".format(self.current_time)]
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

    def copy_blk_file(self, truncate_file=True):
        """
        Copies the first blk file from the regtest directory to the output directory
        :param truncate_file: Whether the final block file should be truncated. Works with BlockSci, but may not work
        when using other parsers.
        """
        blk_destination = self.output_dir + self.chain + "/regtest/blocks/"
        self.log.info("Copying blk00000.dat to {}".format(blk_destination))
        if not os.path.exists(blk_destination):
            os.makedirs(blk_destination)
        source = "{}/regtest/blocks/blk00000.dat".format(self.tempdir.name)

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
        self.copy_blk_file()
        self.persist_hashes()
