
import requests
import logging


logger = logging.getLogger('NotificationHandler')


class PortalConnection(object):

    BASE_URL = "https://portal.sesam.io/api/"
    logger = logging.getLogger('NotificationHandler')

    def __init__(self, jwt):
        self.jwt = jwt
        headers = {
            "Authorization": f"Bearer {jwt}"
        }
        self.session = session = requests.Session()
        session.headers = headers

    def get_subscription_roles(self, subscription_id):
        url = self.BASE_URL + f"subscriptions/{subscription_id}/available-roles"
        resp = self.session.get(url)
        if not resp.ok:
            logger.error(f'Failed to fetch roles for subscription : {subscription_id},returned Error:{resp.text}')
        return resp.json()

    def get_subscription_members(self, subscription_id):
        url = self.BASE_URL + f"subscriptions/{subscription_id}/members"
        resp = self.session.get(url)
        if not resp.ok:
            logger.error(f'Failed to fetch members for subscription : {subscription_id},returned Error:{resp.text}')
        return resp.json()

    def get_pipe_notification_rules(self, subscription_id, pipe_id):
        url = self.get_subscription_pipes_url(subscription_id) + f"{pipe_id}/notification-rules"
        resp = self.session.get(url)
        return resp.json()

    def add_pipe_notification_rule(self, subscription_id, pipe_id, rule):
        url = self.get_subscription_pipes_url(subscription_id) + f"{pipe_id}/notification-rules"
        resp = self.session.post(url, json=rule)
        if resp.ok:
            logger.info(f"Created the notification rule: '{rule.get('name')}' for pipe: '{pipe_id}'. ")
        else:
            logger.error(f"Failed to add notification rule for pipe: '{pipe_id}', Error: '{resp.text}' ")

    def get_pipe_notification_rule(self, subscription_id, pipe_id, notification_rule_id):
        url = self.get_subscription_pipes_url(subscription_id) + f"{pipe_id}/notification-rules/{notification_rule_id}"
        resp = self.session.get(url)
        return resp.json()

    def update_pipe_notification_rule(self, subscription_id, pipe_id, notification_rule_id, rule_definition):
        url = self.get_subscription_pipes_url(subscription_id) + f"{pipe_id}/notification-rules/{notification_rule_id}"
        resp = self.session.put(url, json=rule_definition)
        if resp.ok:
            logger.info(f"Updated existing notification rule : '{rule_definition.get('name')}' for pipe: '{pipe_id}'. ")
        else:
            logger.error("Failed to update notification rule for pipe '{pipe_id}'. Error: '{error}"
                         .format(pipe_id=pipe_id, error=resp.text))
        return resp.status_code

    def delete_pipe_notification_rule(self, subscription_id, pipe_id, notification_rule_id, notification_name):
        url = self.get_subscription_pipes_url(subscription_id) + f"{pipe_id}/notification-rules/{notification_rule_id}"
        resp = self.session.delete(url)
        if resp.ok:
            logger.info(
                    f"Deleted existing notification rule : '{notification_name}' for pipe: '{pipe_id}'. ")
        else:
            logger.error("Failed to delete notification rule for pipe '{pipe_id}'. Error: '{error}"

                         .format(pipe_id=pipe_id, error=resp.text))
        return resp.status_code

    def get_subscription_pipes_url(self, subscription_id):
        return self.BASE_URL + f"subscriptions/{subscription_id}/pipes/"
