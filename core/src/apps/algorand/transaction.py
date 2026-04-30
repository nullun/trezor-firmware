from trezor.wire import DataError

from .msgpack import MsgPackDecoder, msgpack_encode
from .types import TxType, TX_TYPE_STRINGS


class Transaction:
    """Parsed Algorand transaction."""

    def __init__(self, serialized_tx: bytes) -> None:
        decoder = MsgPackDecoder(serialized_tx)
        raw = decoder.read_map()
        decoder.ensure_finished()

        if not isinstance(raw, dict):
            raise DataError("Invalid transaction")

        canonical = msgpack_encode(raw)
        if canonical != serialized_tx:
            raise DataError("Transaction must use canonical MsgPack")

        self.raw = raw
        self.serialized_tx = canonical
        self.tx_type = self._parse_type(raw)
        self.sender: bytes = self._require_bytes(raw, "snd", expected_len=32)
        self.fee: int = self._parse_uint(raw, "fee", 0)
        self.first_valid: int = self._require_uint(raw, "fv")
        self.last_valid: int = self._require_uint(raw, "lv")
        self.genesis_hash: bytes = self._require_bytes(raw, "gh", expected_len=32)
        self.genesis_id: str | None = self._parse_str(raw, "gen")
        self.lease: bytes | None = self._parse_optional_bytes(raw, "lx", 32)
        self.group_id: bytes | None = self._parse_optional_bytes(raw, "grp", 32)
        self.note: bytes | None = self._parse_optional_bin(raw, "note")
        self.rekey: bytes | None = self._parse_optional_bytes(raw, "rekey", 32)

        self.type_data = self._parse_type_specific(raw)

    @staticmethod
    def _parse_type(raw: dict) -> int:
        type_str = raw.get("type")
        if not isinstance(type_str, str):
            raise DataError("Missing transaction type")
        tx_type = TX_TYPE_STRINGS.get(type_str)
        if tx_type is None:
            raise DataError("Unknown transaction type")
        return tx_type

    @staticmethod
    def _is_uint(val: object) -> bool:
        return isinstance(val, int) and not isinstance(val, bool) and val >= 0

    @classmethod
    def _require_bytes(
        cls, raw: dict, key: str, expected_len: int | None = None
    ) -> bytes:
        val = raw.get(key)
        if not isinstance(val, bytes):
            raise DataError(f"Missing required field: {key}")
        if expected_len is not None and len(val) != expected_len:
            raise DataError(f"Invalid field: {key}")
        return val

    @classmethod
    def _require_uint(cls, raw: dict, key: str) -> int:
        val = raw.get(key)
        if val is None:
            raise DataError(f"Missing required field: {key}")
        if not cls._is_uint(val):
            raise DataError(f"Invalid field: {key}")
        return val

    @classmethod
    def _parse_uint(cls, raw: dict, key: str, default: int = 0) -> int:
        val = raw.get(key)
        if val is None:
            return default
        if not cls._is_uint(val):
            raise DataError(f"Invalid field: {key}")
        return val

    @classmethod
    def _parse_optional_uint(cls, raw: dict, key: str) -> int | None:
        val = raw.get(key)
        if val is None:
            return None
        if not cls._is_uint(val):
            raise DataError(f"Invalid field: {key}")
        return val

    @staticmethod
    def _require_bool(raw: dict, key: str) -> bool:
        val = raw.get(key)
        if not isinstance(val, bool):
            raise DataError(f"Missing required field: {key}")
        return val

    @staticmethod
    def _parse_bool(raw: dict, key: str, default: bool = False) -> bool:
        val = raw.get(key)
        if val is None:
            return default
        if not isinstance(val, bool):
            raise DataError(f"Invalid field: {key}")
        return val

    @staticmethod
    def _parse_str(raw: dict, key: str) -> str | None:
        val = raw.get(key)
        if val is None:
            return None
        if not isinstance(val, str):
            raise DataError(f"Invalid field: {key}")
        return val

    @staticmethod
    def _parse_optional_bytes(raw: dict, key: str, expected_len: int) -> bytes | None:
        val = raw.get(key)
        if val is None:
            return None
        if not isinstance(val, bytes) or len(val) != expected_len:
            raise DataError(f"Invalid field: {key}")
        return val

    @staticmethod
    def _parse_optional_bin(raw: dict, key: str) -> bytes | None:
        val = raw.get(key)
        if val is None:
            return None
        if not isinstance(val, bytes):
            raise DataError(f"Invalid field: {key}")
        return val

    def _parse_type_specific(self, raw: dict) -> dict:
        if self.tx_type == TxType.PAYMENT:
            return self._parse_payment(raw)
        elif self.tx_type == TxType.KEYREG:
            return self._parse_keyreg(raw)
        elif self.tx_type == TxType.ASSET_XFER:
            return self._parse_asset_xfer(raw)
        elif self.tx_type == TxType.ASSET_FREEZE:
            return self._parse_asset_freeze(raw)
        elif self.tx_type == TxType.ASSET_CONFIG:
            return self._parse_asset_config(raw)
        elif self.tx_type == TxType.APPLICATION:
            return self._parse_application(raw)
        raise DataError("Unknown transaction type")

    def _parse_payment(self, raw: dict) -> dict:
        return {
            "receiver": self._require_bytes(raw, "rcv", expected_len=32),
            "amount": self._parse_uint(raw, "amt", 0),
            "close_to": self._parse_optional_bytes(raw, "close", 32),
        }

    def _parse_keyreg(self, raw: dict) -> dict:
        return {
            "vote_pk": self._parse_optional_bytes(raw, "votekey", 32),
            "vrf_pk": self._parse_optional_bytes(raw, "selkey", 32),
            "sprf_pk": self._parse_optional_bytes(raw, "sprfkey", 64),
            "vote_first": self._parse_optional_uint(raw, "votefst"),
            "vote_last": self._parse_optional_uint(raw, "votelst"),
            "key_dilution": self._parse_optional_uint(raw, "votekd"),
            "nonpart": self._parse_bool(raw, "nonpart", False),
        }

    def _parse_asset_xfer(self, raw: dict) -> dict:
        return {
            "asset_id": self._require_uint(raw, "xaid"),
            "amount": self._parse_uint(raw, "aamt", 0),
            "receiver": self._require_bytes(raw, "arcv", expected_len=32),
            "sender": self._parse_optional_bytes(raw, "asnd", 32),
            "close_to": self._parse_optional_bytes(raw, "aclose", 32),
        }

    def _parse_asset_freeze(self, raw: dict) -> dict:
        return {
            "asset_id": self._require_uint(raw, "faid"),
            "account": self._require_bytes(raw, "fadd", expected_len=32),
            "frozen": self._require_bool(raw, "afrz"),
        }

    def _parse_asset_config(self, raw: dict) -> dict:
        result: dict = {
            "asset_id": self._parse_uint(raw, "caid", 0),
        }
        apar = raw.get("apar")
        if apar is not None:
            if not isinstance(apar, dict):
                raise DataError("Invalid field: apar")
            params: dict = {}
            if "t" in apar:
                params["total"] = self._require_uint(apar, "t")
            if "dc" in apar:
                params["decimals"] = self._require_uint(apar, "dc")
            if "df" in apar:
                params["default_frozen"] = self._require_bool(apar, "df")
            if "un" in apar:
                un = apar["un"]
                if not isinstance(un, str) or len(un) > 8:
                    raise DataError("Invalid unit name")
                params["unit_name"] = un
            if "an" in apar:
                an = apar["an"]
                if not isinstance(an, str) or len(an) > 32:
                    raise DataError("Invalid asset name")
                params["asset_name"] = an
            if "au" in apar:
                au = apar["au"]
                if not isinstance(au, str) or len(au) > 96:
                    raise DataError("Invalid URL")
                params["url"] = au
            if "am" in apar:
                am = apar["am"]
                if not isinstance(am, bytes) or len(am) != 32:
                    raise DataError("Invalid metadata hash")
                params["metadata_hash"] = am
            if "m" in apar:
                params["manager"] = self._require_bytes(apar, "m", expected_len=32)
            if "r" in apar:
                params["reserve"] = self._require_bytes(apar, "r", expected_len=32)
            if "f" in apar:
                params["freeze"] = self._require_bytes(apar, "f", expected_len=32)
            if "c" in apar:
                params["clawback"] = self._require_bytes(
                    apar, "c", expected_len=32
                )
            result["params"] = params
        return result

    def _parse_application(self, raw: dict) -> dict:
        from .types import OnCompletion

        result: dict = {
            "app_id": self._parse_uint(raw, "apid", 0),
        }

        if "apan" in raw:
            oc = raw["apan"]
            if not self._is_uint(oc) or oc > 5:
                raise DataError("Invalid OnCompletion value")
            result["on_completion"] = oc

        # Application arguments
        if "apaa" in raw:
            args = raw["apaa"]
            if not isinstance(args, list) or len(args) > 16:
                raise DataError("Invalid app args")
            for arg in args:
                if not isinstance(arg, bytes) or len(arg) > 2048:
                    raise DataError("Invalid app arg")
            result["app_args"] = args
            result["num_app_args"] = len(args)

        # Accounts
        if "apat" in raw:
            accounts = raw["apat"]
            if not isinstance(accounts, list) or len(accounts) > 8:
                raise DataError("Invalid accounts")
            for acct in accounts:
                if not isinstance(acct, bytes) or len(acct) != 32:
                    raise DataError("Invalid account")
            result["accounts"] = accounts
            result["num_accounts"] = len(accounts)

        # Foreign apps
        if "apfa" in raw:
            apps = raw["apfa"]
            if not isinstance(apps, list) or len(apps) > 8:
                raise DataError("Invalid foreign apps")
            for app in apps:
                if not self._is_uint(app):
                    raise DataError("Invalid foreign apps")
            result["foreign_apps"] = apps
            result["num_foreign_apps"] = len(apps)

        # Foreign assets
        if "apas" in raw:
            assets = raw["apas"]
            if not isinstance(assets, list) or len(assets) > 8:
                raise DataError("Invalid foreign assets")
            for asset in assets:
                if not self._is_uint(asset):
                    raise DataError("Invalid foreign assets")
            result["foreign_assets"] = assets
            result["num_foreign_assets"] = len(assets)

        # Validate combined access list constraint
        num_accounts = result.get("num_accounts", 0)
        num_foreign_apps = result.get("num_foreign_apps", 0)
        num_foreign_assets = result.get("num_foreign_assets", 0)
        if num_accounts + num_foreign_apps + num_foreign_assets > 8:
            raise DataError("Too many references in application call")

        # Boxes
        if "apbx" in raw:
            boxes = raw["apbx"]
            if not isinstance(boxes, list) or len(boxes) > 8:
                raise DataError("Invalid boxes")
            parsed_boxes: list[dict] = []
            for box in boxes:
                if not isinstance(box, dict):
                    raise DataError("Invalid box")
                app_index = box.get("i")
                name = box.get("n")
                if (
                    len(box) != 2
                    or not self._is_uint(app_index)
                    or app_index > 0xFF
                    or not isinstance(name, bytes)
                ):
                    raise DataError("Invalid box")
                parsed_boxes.append({"i": app_index, "n": name})
            result["boxes"] = parsed_boxes

        # State schemas
        if "apls" in raw:
            schema = raw["apls"]
            if not isinstance(schema, dict):
                raise DataError("Invalid local schema")
            result["local_schema"] = self._parse_state_schema(schema)
        if "apgs" in raw:
            schema = raw["apgs"]
            if not isinstance(schema, dict):
                raise DataError("Invalid global schema")
            result["global_schema"] = self._parse_state_schema(schema)

        # Extra pages
        if "apep" in raw:
            ep = raw["apep"]
            if not self._is_uint(ep) or ep > 3:
                raise DataError("Invalid extra pages")
            result["extra_pages"] = ep

        # Programs
        if "apap" in raw:
            result["approval_program"] = self._require_bytes(raw, "apap")
        if "apsu" in raw:
            result["clear_program"] = self._require_bytes(raw, "apsu")

        # Reject version
        if "aprv" in raw:
            result["reject_version"] = self._require_uint(raw, "aprv")

        # Access list
        if "al" in raw:
            al = raw["al"]
            if not isinstance(al, list) or len(al) > 16:
                raise DataError("Invalid access list")
            self._validate_access_list(al)
            result["access_list"] = al

        return result

    @classmethod
    def _parse_state_schema(cls, schema: dict) -> dict:
        return {
            "num_uint": cls._parse_uint(schema, "nui", 0),
            "num_byteslice": cls._parse_uint(schema, "nbs", 0),
        }

    @classmethod
    def _validate_access_list(cls, access_list: list) -> None:
        for entry in access_list:
            if not isinstance(entry, dict):
                raise DataError("Invalid access list")
            keys = [key for key in ("d", "p", "s", "h", "l", "b") if key in entry]
            if len(keys) != 1:
                raise DataError("Invalid access list")
            key = keys[0]
            value = entry[key]
            if key == "d":
                if not isinstance(value, bytes) or len(value) != 32:
                    raise DataError("Invalid access list")
            elif key in ("p", "s"):
                if not cls._is_uint(value):
                    raise DataError("Invalid access list")
            elif not isinstance(value, dict):
                raise DataError("Invalid access list")
