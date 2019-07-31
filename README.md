### Node-notification-handler

` Example of a system-config for this micro-service.`

```json
{
  "_id": "<Name of the system>",
  "type": "system:microservice",
  "docker": {
    "environment": {
      "LOG_LEVEL": "INFO",
      "jwt": "<token to access node>",
      "sesam_node_url": "https://<your node URL>.sesam.cloud/api"
    },
    "image": "<docker image path-name>",
    "port": 5000
  },
  "verify_ssl": true
}
```

**`Now, to use this micro-service,you need to add mandatory "metadata" tag in your required pipe configuration.
Below, is one example of creating one such automatic rule for pipe "test-notifications".`**

```json
{
  "_id": "<Name of pipe>",
  "type": "pipe",
  "metadata": {
    "notifications": {
      "rules": [{
        "type": "pump_completed_value_too_high",
        "name": "entities changed",
        "description": "test rule 1",
        "extra_rule_info": {
          "limit": 50,
          "parameter": "changes_last_run"
        },
        "recipients": ["ravish.ranjan@sesam.io", "Admin"]
      },
      {
        "type": "pump_completed_value_too_low_over_time",
        "name": "at-least-1-change-in-last-3-days",
        "description": "Notify if we exceed the api rate limit per hour",
        "extra_rule_info": {
          "interval": 259200,
          "limit": 1,
          "parameter": "changes_last_run"
        },
        "recipients": ["ravish.ranjan@sesam.io"]
      }
      ]
      }
    }
}
```
    Few things to follow :
        1. Sub tags like "notifications" and "rules" are mandatory. All tags and values are case-sensitive.
        2. "type", "name", "description", "extra_rule_info" and "recipients" tags are also mandatory ones.
        3. As you can see "rules" is list,so you can can create multiple rules through configuration.
        4. "recipients" are comma separated values of "users" and "roles" defined or exist on that node.
        5. "type and ""extra_rule_info" tags configuration should follow the same rule\format that we follow
            during manual-creation of the notification rule.if not, you will see error message in logs.
        6. Please be informed that any manually created rule will be deleted and only those rule will be there which
            will be part of that pipe-config.
