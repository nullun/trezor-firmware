class AssetInfo:
    def __init__(self, asset_id: int, name: str, unit: str, decimals: int) -> None:
        self.asset_id = asset_id
        self.name = name
        self.unit = unit
        self.decimals = decimals

    @property
    def display_name(self) -> str:
        if self.name:
            return f"{self.name} ({self.asset_id})"
        return str(self.asset_id)


_ASA_DB: dict[int, tuple[str, str, int]] = {
    312769: ("Tether USDt", "USDt", 6),
    31566704: ("USDC", "USDC", 6),
}


def get_asset_info(asset_id: int) -> AssetInfo:
    entry = _ASA_DB.get(asset_id)
    if entry is not None:
        return AssetInfo(
            asset_id=asset_id,
            name=entry[0],
            unit=entry[1],
            decimals=entry[2],
        )
    return AssetInfo(
        asset_id=asset_id,
        name="",
        unit="Base unit",
        decimals=0,
    )
