# This file is part of the Trezor project.
#
# Copyright (C) SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

"""
Central place for defining all input flows for the device tests.

Each class emulates a sequence of user interactions driving the Algorand
app's review screens. Tests attach a flow with
``client.set_input_flow(InputFlowX(client).get())``.
"""

from typing import TYPE_CHECKING, Generator

if TYPE_CHECKING:
    from trezorlib import messages
    from trezorlib.debuglink import DebugLink, SessionDebugWrapper

InputFlowType = Generator[None, "messages.ButtonRequest", None]


class InputFlowBase:
    def __init__(self, client: "SessionDebugWrapper"):
        self.client = client
        self.debug: DebugLink = client.debug

    def get(self) -> InputFlowType:
        # Only one input flow is expected to be defined.
        return self.input_flow()

    def input_flow(self) -> InputFlowType:
        """Delegate to the subclass's flow."""
        raise NotImplementedError

    def _page_to_end(self) -> None:
        """Advance a paginated review screen to its last page."""
        layout = self.debug.read_layout()
        for _ in range(max(0, layout.page_count() - 1)):
            self.debug.click(self.debug.screen_buttons.ok())
            layout = self.debug.read_layout()


class InputFlowConfirmAll(InputFlowBase):
    """Page to the end of every review screen, then confirm it.

    Uses the framework's semantic confirm (`DebugButton.YES` via
    `press_yes()`), the same primitive the default input flow relies on.
    Unlike a coordinate tap it completes hold-to-confirm screens directly —
    no manual `hold_ms` — and it works whether or not animations are enabled.
    """

    def input_flow(self) -> InputFlowType:
        while True:
            yield
            self._page_to_end()
            self.debug.press_yes()


class InputFlowSignTxCancel(InputFlowBase):
    """Reject the first review screen, cancelling the whole flow."""

    def input_flow(self) -> InputFlowType:
        yield
        self.debug.press_no()
