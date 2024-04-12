# contextmanager to facilitate connecting to card token
class PKCS11Session(object):
    def __init__(self):
        # session for interacton with the card
        self._session = None
        # does user need to be logged in to use session
        self._login_required = False

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()

    async def __aexit__(self, exc_type, exc_value, traceback):
        ret = False
        self.close()
        return ret

    # Closing work on an open session
    def close(self):
        if self._session is not None:
            if self._login_required:
                self._session.logout()
            self._session.closeSession()
            self._session = None
