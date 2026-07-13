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

"""Drive the Algorand app's on-device review screens from tests.

Uses the framework's semantic confirm (`DebugButton.YES` via `press_yes()`),
the same primitive the default input flow relies on. Unlike a coordinate tap,
it completes hold-to-confirm screens directly — no manual `hold_ms` — and it
works whether or not animations are enabled.
"""

from . import algorand_ext


def confirm_flow(client):
    """Input flow: page to the end of each review screen, then confirm."""
    debug = client.debug
    while True:
        yield
        layout = debug.read_layout()
        for _ in range(max(0, layout.page_count() - 1)):
            debug.click(debug.screen_buttons.ok())
            layout = debug.read_layout()
        debug.press_yes()


def sign(session, instance_id, address_n, transactions, **kwargs):
    """Sign `transactions`, auto-confirming every review screen."""
    with session.test_ctx as client:
        client.set_input_flow(confirm_flow(client))
        return algorand_ext.sign_transactions(
            session, instance_id, address_n, transactions, **kwargs
        )
