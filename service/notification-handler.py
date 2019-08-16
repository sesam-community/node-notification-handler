#!/usr/bin/env python3

import datetime
import logging
import os

import requests
import sesamclient
from portal import PortalConnection
from validate_email import validate_email

__author__ = "Ravish Ranjan"

# Get all the environment variables values from sesam node instance e.g http://sesam-node:9042/api
sesam_node_url = os.environ.get('sesam_node_url')  # Sesam node url
jwt = os.environ.get('jwt')

# set logging
logger = logging.getLogger('NotificationHandler')
logger.setLevel({"INFO": logging.INFO,
                 "DEBUG": logging.DEBUG,
                 "WARNING": logging.WARNING,
                 "ERROR": logging.ERROR}.get(os.getenv("LOG_LEVEL", "INFO")))  # Default log level: INFO
stdout_handler = logging.StreamHandler()
stdout_handler.setFormatter(logging.Formatter('%(name)s - %(levelname)s - %(message)s'))
logger.addHandler(stdout_handler)


logger.info("sesam instance name: %s" % sesam_node_url)

node_conn = sesamclient.Connection(
    sesamapi_base_url=sesam_node_url,
    jwt_auth_token=jwt,
    timeout=60)
portal_conn = PortalConnection(jwt)

subscription_id = node_conn.get_license().get("_id")
logger.debug(f"Node subscription_id: '{subscription_id}'")


def get_sesam_node_pipe_notification_list():
    try:
        pipes = node_conn.get_pipes()
        pipe_rules = list()
        for each_pipe in pipes:
            if each_pipe.config['original'].get('metadata') is not None and \
                    each_pipe.config['original']['metadata'].get('notifications') is not None:
                pipe_id = each_pipe.id
                pipe_rules = each_pipe.config['original']['metadata']['notifications']
                process_pipe_rules(pipe_id, pipe_rules)
    except requests.ConnectionError:
        logger.error(f'Issue while working with subscription {subscription_id}')


def validate_rule_tags(rule):
    missing_required_tag = list()
    if rule.get('type') is None:
        missing_required_tag.append("type")
    if rule.get('extra_rule_info') is None:
        missing_required_tag.append("extra_rule_info")
    if rule.get('recipients') is None:
        missing_required_tag.append("recipients")
    if rule.get('name') is None:
        missing_required_tag.append("name")
    if rule.get('description') is None:
        missing_required_tag.append("description")
    return missing_required_tag


def process_pipe_rules(pipe_id, pipe_rules):
    if pipe_rules and pipe_rules.get('rules') is not None:
        existing_rules = portal_conn.get_pipe_notification_rules(subscription_id, pipe_id)
        update_count = 0
        matched_existence_rules = list()
        node_members_and_roles = get_node_members_and_roles()
        for rule in pipe_rules['rules']:
            same_name_existing_rule = None
            missing_rule_tags = validate_rule_tags(rule)
            if missing_rule_tags:
                logger.error(f"Required tags {missing_rule_tags} of pipe '{pipe_id}' are missing"
                              f" for this rule {rule}.So,this notification-rule will not create.")
                continue
            try:
                recipients = list()
                if rule.get('recipients') is not None:
                    for item in rule['recipients']:
                        recipient = dict()
                        recipient = {"id": node_members_and_roles[item],
                                     "methods": ["email"],
                                     "type": ''}
                        if validate_email(item):
                            recipient['type'] = 'user_id'
                        else:
                            recipient["type"] = 'role'
                        recipients.append(recipient)
                rule['recipients'] = recipients  # update the recipients as per API format
            except KeyError:
                logger.error(
                    f"Provided recipient name: '{item}' is not correct for pipe: '{pipe_id}'.This rule will skip.")
                continue
            for existing_rule in existing_rules:
                if existing_rule.get("name") == rule.get("name"):
                    same_name_existing_rule = existing_rule
                    rule["id"] = existing_rule.get("id")
                    matched_existence_rules.append(same_name_existing_rule)

            if not rule == same_name_existing_rule:
                if same_name_existing_rule:
                    # updating existing rule
                    portal_conn.update_pipe_notification_rule(subscription_id, pipe_id, rule.get("id"), rule)
                else:
                    # creating new rule
                    portal_conn.add_pipe_notification_rule(subscription_id, pipe_id, rule)
                update_count += 1

    if update_count == 0:
        logger.debug("No new/changed rules found for pipe '{}'".format(pipe_id))
    # Delete the manually created notifications rule if any
    for existing in existing_rules:
        if existing not in matched_existence_rules:
            portal_conn.delete_pipe_notification_rule(subscription_id, pipe_id,
                                                      existing.get("id"), existing.get("name"))


def get_node_members_and_roles():
    node_members = portal_conn.get_subscription_members(subscription_id)
    node_members_and_roles = dict()
    for member in node_members:
        node_members_and_roles[member['user']['email']] = member['user']['user_id']
    node_roles = portal_conn.get_subscription_roles(subscription_id)
    for role in node_roles:
        node_members_and_roles[role['name']] = role['id']
    return node_members_and_roles


if __name__ == '__main__':
    get_sesam_node_pipe_notification_list()
