# Token representation
class PKCS11SlotAdmin:
    def __init__(self, session):
        # session for interacton with the card
        self._session = session

    # Init pin for a card
    def init_pin(self, pin: str):
        if self._session != None:
            self._session.initPin(pin)

    # Change pin for the card
    def change_pin(self, old_pin: str, new_pin: str):
        if self._session != None:
            self._session.setPin(old_pin, new_pin)
