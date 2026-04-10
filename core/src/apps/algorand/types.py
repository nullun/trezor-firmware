from micropython import const


class TxType:
    UNKNOWN = const(0)
    PAYMENT = const(1)
    KEYREG = const(2)
    ASSET_XFER = const(3)
    ASSET_FREEZE = const(4)
    ASSET_CONFIG = const(5)
    APPLICATION = const(6)


class OnCompletion:
    NOOP = const(0)
    OPT_IN = const(1)
    CLOSE_OUT = const(2)
    CLEAR_STATE = const(3)
    UPDATE_APP = const(4)
    DELETE_APP = const(5)


TX_TYPE_STRINGS = {
    "pay": TxType.PAYMENT,
    "keyreg": TxType.KEYREG,
    "axfer": TxType.ASSET_XFER,
    "afrz": TxType.ASSET_FREEZE,
    "acfg": TxType.ASSET_CONFIG,
    "appl": TxType.APPLICATION,
}

TX_TYPE_NAMES = {
    TxType.PAYMENT: "Payment",
    TxType.KEYREG: "Key Registration",
    TxType.ASSET_XFER: "Asset Transfer",
    TxType.ASSET_FREEZE: "Asset Freeze",
    TxType.ASSET_CONFIG: "Asset Config",
    TxType.APPLICATION: "Application Call",
}

TX_TYPE_ABBREVS = {
    TxType.PAYMENT: "pay",
    TxType.KEYREG: "keyreg",
    TxType.ASSET_XFER: "axfer",
    TxType.ASSET_FREEZE: "afrz",
    TxType.ASSET_CONFIG: "acfg",
    TxType.APPLICATION: "appl",
}

ON_COMPLETION_NAMES = {
    OnCompletion.NOOP: "NoOp",
    OnCompletion.OPT_IN: "OptIn",
    OnCompletion.CLOSE_OUT: "CloseOut",
    OnCompletion.CLEAR_STATE: "ClearState",
    OnCompletion.UPDATE_APP: "UpdateApp",
    OnCompletion.DELETE_APP: "DeleteApp",
}
