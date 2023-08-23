#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Dmitriy Shemin <me@shemindmitry.tech>
from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.wikijs import finalize, FinalizeRequest

__metaclass__ = type

DOCUMENTATION = r"""
---
module: wikijs_finalize

short_description: Finalize WikiJS setup

version_added: "1.0.0"

description: Finalize WikiJS setup

options:
    endpoint:
        description: The WikiJS' API endpoint.
        required: true
        type: str
    admin_email:
        description: Administration email.
        required: true
        type: str
    admin_password:
        description: Administration password.
        required: true
        type: str
    site_url:
        description: Site url.
        required: true
        type: str
    telemetry:
        description: Enable/disable telemetry.
        optional: true
        type: bool
        default: false

author:
    - Dmitry Shemin (@dshemin)
"""

EXAMPLES = r"""
# Pass in a message
- name: Test with a message
  my_namespace.my_collection.my_test:
    name: hello world

# pass in a message and have changed true
- name: Test with a message and changed output
  my_namespace.my_collection.my_test:
    name: hello world
    new: true

# fail the module
- name: Test failure of the module
  my_namespace.my_collection.my_test:
    name: fail me
"""

RETURN = r"""
# These are examples of possible return values, and in general should use other names for return values.
original_message:
    description: The original name param that was passed in.
    type: str
    returned: always
    sample: 'hello world'
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: 'goodbye'
"""


def run_module() -> None:
    module_args = {
        "endpoint": {
            "type": "str",
            "required": True,
        },
        "admin_email": {
            "type": "str",
            "required": True,
        },
        "admin_password": {
            "type": "str",
            "required": True,
            "no_log": True,
        },
        "site_url": {
            "type": "str",
            "required": True,
        },
        "telemetry": {
            "type": "bool",
            "optional": True,
            "default": False,
        },
    }

    result = {
        "changed": False,
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if module.check_mode:
        module.exit_json(**result)

    req = FinalizeRequest(
        module.params["admin_email"],
        module.params["admin_password"],
        module.params["site_url"],
        module.params["telemetry"],
    )

    res = finalize(module.params["endpoint"], req)

    if res[1] != "":
        module.fail_json(msg=res[1])

    result["changed"] = res[0]

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
