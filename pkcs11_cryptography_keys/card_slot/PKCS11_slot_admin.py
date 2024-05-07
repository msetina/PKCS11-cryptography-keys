# Token representation
class PKCS11SlotAdmin:
    def __init__(self, session):
        # session for interacton with the card
        self._session = session

    # Init pin for a card (user pin)
    # SO pin is initialized with token creation
    def init_pin(self, pin: str) -> None:
        if self._session != None:
            self._session.initPin(pin)

    # Change pin for the card
    # If session is open with SO PIN the change is made on SO otherwise normal pin
    def change_pin(self, old_pin: str, new_pin: str) -> None:
        if self._session != None:
            self._session.setPin(old_pin, new_pin)
