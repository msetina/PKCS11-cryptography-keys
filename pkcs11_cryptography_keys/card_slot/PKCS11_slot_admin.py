# Token representation
from logging import getLogger

from ..utils.exceptions import PinException
from ..utils.token_properties import PinState, TokenProperties


class PKCS11SlotAdmin:
    def __init__(self, session, token_properties: TokenProperties, logger=None):
        # session for interacton with the card
        self._session = session
        self._token_properties = token_properties
        self._logger = (
            logger if logger is not None else getLogger("PKCS11SlotAdmin")
        )

    # Init pin for a card (user pin)
    # SO pin is initialized with token creation
    def init_pin(self, pin: str) -> None:
        if not self._token_properties.check_pin_length(pin):
            raise PinException("User pin is to long or to short for the token")
        if self._session != None:
            self._session.initPin(pin)

    # Change pin for the card
    # If session is open with SO PIN the change is made on SO otherwise normal pin
    def change_pin(self, old_pin: str, new_pin: str) -> None:
        if not self._token_properties.check_pin_length(new_pin):
            raise PinException(
                "New user pin is to long or to short for the token"
            )
        if self._session != None:
            self._session.setPin(old_pin, new_pin)

    def get_user_pin_state(self) -> PinState:
        return self._token_properties.get_user_pin_state()

    def get_so_pin_state(self) -> PinState:
        return self._token_properties.get_so_pin_state()
