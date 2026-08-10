# Copyright Notice:
# Copyright 2016-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

"""Standard Redfish resource models used by the asynchronous client."""

from dataclasses import dataclass
from typing import FrozenSet, Optional


STANDARD_RESET_TYPES = frozenset(
    {
        "ForceOff",
        "ForceOn",
        "ForceRestart",
        "FullPowerCycle",
        "GracefulRestart",
        "GracefulShutdown",
        "Nmi",
        "On",
        "Pause",
        "PowerCycle",
        "PushPowerButton",
        "Resume",
        "Suspend",
    }
)


@dataclass(frozen=True)
class ComputerSystem:
    """Standard properties and reset capabilities of a ComputerSystem."""

    odata_id: str
    system_id: str
    name: Optional[str]
    uuid: Optional[str]
    manufacturer: Optional[str]
    model: Optional[str]
    serial_number: Optional[str]
    power_state: Optional[str]
    reset_target: Optional[str]
    reset_types: FrozenSet[str]


def _non_empty_string(value):
    return value if isinstance(value, str) and value.strip() else None


def _reset_action(payload):
    actions = payload.get("Actions")
    if not isinstance(actions, dict):
        return None
    reset = actions.get("#ComputerSystem.Reset")
    return reset if isinstance(reset, dict) else None


def get_reset_action_info_target(payload):
    """Return the ActionInfo target advertised for ComputerSystem.Reset."""
    reset = _reset_action(payload)
    if reset is None:
        return None
    return _non_empty_string(reset.get("@Redfish.ActionInfo"))


def parse_reset_action_info(payload):
    """Return standard ResetType values from an ActionInfo resource."""
    parameters = payload.get("Parameters")
    if not isinstance(parameters, list):
        return frozenset()
    for parameter in parameters:
        if (
            not isinstance(parameter, dict)
            or parameter.get("Name") != "ResetType"
        ):
            continue
        allowable_values = parameter.get("AllowableValues")
        if not isinstance(allowable_values, list):
            return frozenset()
        return frozenset(
            value
            for value in allowable_values
            if isinstance(value, str) and value in STANDARD_RESET_TYPES
        )
    return frozenset()


def parse_computer_system(payload):
    """Parse a ComputerSystem resource or return None when unusable."""
    odata_id = _non_empty_string(payload.get("@odata.id"))
    system_id = _non_empty_string(payload.get("Id"))
    if odata_id is None or system_id is None:
        return None

    reset_target = None
    reset_types = frozenset()
    reset = _reset_action(payload)
    if reset is not None:
        reset_target = _non_empty_string(reset.get("target"))
        allowable_values = reset.get("ResetType@Redfish.AllowableValues")
        if reset_target is not None and isinstance(allowable_values, list):
            reset_types = frozenset(
                value
                for value in allowable_values
                if isinstance(value, str) and value in STANDARD_RESET_TYPES
            )

    return ComputerSystem(
        odata_id=odata_id,
        system_id=system_id,
        name=_non_empty_string(payload.get("Name")),
        uuid=_non_empty_string(payload.get("UUID")),
        manufacturer=_non_empty_string(payload.get("Manufacturer")),
        model=_non_empty_string(payload.get("Model")),
        serial_number=_non_empty_string(payload.get("SerialNumber")),
        power_state=_non_empty_string(payload.get("PowerState")),
        reset_target=reset_target,
        reset_types=reset_types,
    )
