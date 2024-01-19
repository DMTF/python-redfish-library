#! /usr/bin/python
# Copyright Notice:
# Copyright 2019-2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Tacklebox/blob/main/LICENSE.md

"""
Messages Module

File : messages.py

Brief : This file contains the definitions and functionalities for interacting
        with Messages for a given Redfish service
"""
import re

class RedfishOperationFailedError( Exception ):
    """
    Raised when an operation has failed (HTTP Status >= 400)
    """
    pass

class RedfishPasswordChangeRequiredError( Exception ):
    """
    Raised when password change required
    """
    def __str__(self):
        return  "\n{}\nURL: {}\n".format( str(self.args[0]), str(self.args[1]) )

def get_messages_detail( response ):
    """
    Builds messages detail dict in the payload

    Args:
        response: The response to parser

    Returns:
        The dict containing messages_detail
        messages_detail["status"]: http status code
        messages_detail["successful"]: response successful (http status code < 400)
        messages_detail["code"]: redfish message response code field
        messages_detail["@Message.ExtendedInfo"]: redfish message response code field
    """

    messages_detail = {}
    messages_detail["status"] = response.status
    messages_detail["text"] = response.text
    messages_detail["successful"] = False
    messages_detail["@Message.ExtendedInfo"] = []

    if response.status >= 400:
        messages_detail["successful"] = False
    else:
        messages_detail["successful"] = True

    try:
        message_body = response.dict
        messages_detail["body"] = response.dict

        if not "@Message.ExtendedInfo" in message_body:
            message_body = response.dict["error"]
        check_message_field = True
        if "@Message.ExtendedInfo" in message_body:
            messages_detail["@Message.ExtendedInfo"] = message_body["@Message.ExtendedInfo"]
            for index in range(len(messages_detail["@Message.ExtendedInfo"])):
                messages_item = messages_detail["@Message.ExtendedInfo"][index]
                if not "MessageId" in messages_item:
                    messages_item["MessageId"] = ""
                if not "Message" in messages_item:
                    messages_item["Message"] = ""
                messages_detail["@Message.ExtendedInfo"][index] = messages_item
                check_message_field = False

        if check_message_field is True:
            messages_detail["@Message.ExtendedInfo"] = []
            messages_item = {}
            if "code" in message_body:
                messages_item["MessageId"] = message_body["code"]
            else:
                messages_item["MessageId"] = ""
            if "message" in message_body:
                messages_item["Message"] = message_body["message"]
            else:
                messages_item["Message"] = ""
            messages_detail["@Message.ExtendedInfo"].insert(0, messages_item)
    except:
        messages_detail["@Message.ExtendedInfo"] = []
        messages_detail["body"] = {}

    return messages_detail

def search_message(response, message_registry_group, message_registry_id):
    """
    search message in the payload

    Args:
        response: The response to parser
        message_registry_group: target message_registry_group
        message_registry_id: target message_registry_id
    Returns:
        The dict containing target message detail
    """
    if isinstance(response, dict) and "@Message.ExtendedInfo" in response:
        messages_detail = response
    else:
        messages_detail = get_messages_detail(response)

    message_registry_id_search = "^" + message_registry_group + r"\.[0-9]+\.[0-9]+\." + message_registry_id +"$"

    for messages_item in messages_detail["@Message.ExtendedInfo"]:
        if "MessageId" in messages_item:
            resault = re.search(message_registry_id_search, messages_item["MessageId"])
            if resault:
                return messages_item
    return None

def get_error_messages( response ):
    """
    Builds a string based on the error messages in the payload

    Args:
        response: The response to print

    Returns:
        The string containing error messages
    """

    # Pull out the error payload and the messages

    out_string = ""
    try:
        if isinstance(response, dict) and "@Message.ExtendedInfo" in response:
            messages_detail = response
        else:
            messages_detail = get_messages_detail(response)

        if "@Message.ExtendedInfo" in messages_detail:
            for message in messages_detail["@Message.ExtendedInfo"]:
                if "Message" in message:
                    out_string = out_string + "\n" + message["Message"]
            else:
                    out_string = out_string + "\n" + message["MessageId"]
        out_string = out_string + "\n"
    except:
        # No response body
        out_string = ""

    return out_string

