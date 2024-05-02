from logging import Logger, getLogger


# contextmanager to facilitate connecting to card token
class PKCS11Session(object):
    def __init__(self, logger: Logger | None):
        self._logger = (
            logger if logger is not None else getLogger("PKCS11 session")
        )
        # session for interacton with the card
        self._session = None
        # does user need to be logged in to use session
        self._login_required = False

    def __exit__(self, exc_type, exc_value, exc_traceback):
        ret = False
        self.close()
        if exc_type is not None:
            self._logger.error(
                "PKCS11 session experienced an error : %s",
                exc_value,
                exc_info=True,
            )
        else:
            self._logger.info("PKCS11 session exited successfully")
        return ret

    async def __aexit__(self, exc_type, exc_value, exc_traceback):
        ret = False
        self.close()
        if exc_type is not None:
            self._logger.error(
                "PKCS11 session experienced an error : %s",
                exc_value,
                exc_info=True,
            )
        else:
            self._logger.info("PKCS11 session exited successfully")
        return ret

    # Closing work on an open session
    def close(self):
        if self._session is not None:
            if self._login_required:
                self._session.logout()
            self._session.closeSession()
            self._session = None
