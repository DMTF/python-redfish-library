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

def print_error_payload( response ):
    """
    Prints an error payload, which can also be used for action responses

    Args:
        response: The response to print
    """

    try:
        print( get_error_messages( response ) )
    except:
        # No response body
        if response.status >= 400:
            print( "Failed" )
        else:
            print( "Success" )

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
    messages_detail["successful"] = False
    messages_detail["code"] = ""
    messages_detail["message"] = ""
    messages_detail["@Message.ExtendedInfo"] = []

    if response.status >= 400:
        messages_detail["successful"] = False
    else:
        messages_detail["successful"] = True

    try:
        message_body = response.dict
        if not "@Message.ExtendedInfo" in message_body:
            message_body = response.dict["error"]

        if "code" in message_body:
            messages_detail["code"] = message_body["code"]
        if "message" in message_body:
            messages_detail["message"] = message_body["message"]
        if "@Message.ExtendedInfo" in message_body:
            messages_detail["@Message.ExtendedInfo"] = message_body["@Message.ExtendedInfo"]
    except:
        messages_detail["code"] = ""
        messages_detail["message"] = ""
        messages_detail["@Message.ExtendedInfo"] = []

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
    message_registry_id_search = "^" + message_registry_group + "\.[0-9]+\.[0-9]+\." + message_registry_id +"$"

    for messages_item in messages_detail["@Message.ExtendedInfo"]:
        if "MessageId" in messages_item:
            resault = re.search(message_registry_id_search, messages_item["MessageId"])
            if resault:
                if not "@odata.type" in messages_item:
                    messages_item["@odata.type"] = ""
                if not "RelatedProperties" in messages_item:
                    messages_item["RelatedProperties"] = []
                if not "Message" in messages_item:
                    messages_item["Message"] = ""
                if not "MessageArgs" in messages_item:
                    messages_item["MessageArgs"] = []
                if not "Severity" in messages_item:
                    messages_item["Severity"] = ""
                if not "MessageSeverity" in messages_item:
                    messages_item["MessageSeverity"] = ""
                if not "Resolution" in messages_item:
                    messages_item["Resolution"] = ""
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
        out_string = response.dict["error"]["message"]
        if "@Message.ExtendedInfo" in response.dict["error"]:
            for message in response.dict["error"]["@Message.ExtendedInfo"]:
                if "Message" in message:
                    out_string = out_string + "\n" + message["Message"]
            else:
                    out_string = out_string + "\n" + message["MessageId"]
        out_string = out_string + "\n"
    except:
        # No response body
        out_string = ""

    return out_string

def verify_response( response ):
    """
    Verifies a response and raises an exception if there was a failure

    Args:
        response: The response to verify
    """

    if response.status >= 400:
        exception_string = get_error_messages( response )
        message_item = search_message(response, "Base", "PasswordChangeRequired")
        if not message_item is None:
            raise RedfishPasswordChangeRequiredError( "Operation failed: HTTP {}\n{}".format( response.status, exception_string ), message_item["MessageArgs"][0])
        else:
            raise RedfishOperationFailedError( "Operation failed: HTTP {}\n{}".format( response.status, exception_string ) )

    return
