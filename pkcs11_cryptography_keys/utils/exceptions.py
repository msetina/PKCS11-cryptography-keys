class SessionException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class KeyException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class PinException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class TokenException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class UriException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class CallbackException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)
