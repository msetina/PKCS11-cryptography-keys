from enum import Enum
from typing import Callable


class PinTypes(Enum):
    SO_USER = 1
    NORM_USER = 2


def _get_norm_user_pin(name: str, reason: str) -> str:
    return input("{0} Please enter PIN for {1}:".format(reason, name))


def _get_so_user_pin(name: str, reason: str) -> str:
    return input(
        "{0} Please enter security officer PIN(SO PIN) for {1}:".format(
            reason, name
        )
    )


_default_calls = {
    PinTypes.NORM_USER: _get_norm_user_pin,
    PinTypes.SO_USER: _get_so_user_pin,
}


class Pin4Token(object):
    def __init__(
        self,
        name: str,
        reason: str,
        callbacks: dict[PinTypes, Callable[[str, str], str]] | None = None,
    ) -> None:
        self._name = name
        self._reason = reason
        self._callbacks = callbacks

    def get_pin(self, pin_type: PinTypes) -> str:
        call = None
        ret = None
        if self._callbacks is not None and pin_type in self._callbacks:
            call = self._callbacks[pin_type]
        else:
            call = _default_calls[pin_type]

        if call is not None:
            ret = call(self._name, self._reason)
        else:
            raise Exception("Pin callback not set!")
        return ret
