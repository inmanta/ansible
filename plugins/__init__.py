"""
    Copyright 2017 Inmanta

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    Contact: code@inmanta.com
"""

import tempfile
import os
import re
import json
import logging
import copy

import yaml
from inmanta.agent.handler import provider, ResourceHandler, CRUDHandler
from inmanta.resources import Resource, resource, ResourceNotFoundExcpetion

LOGGER = logging.getLogger(__name__)

@resource("ansible::Task", agent="agent", id_attribute="name")
class Task(Resource):
    fields = ("module", "name", "args", "host")


@provider("ansible::Task", name="task")
class TaskHandler(ResourceHandler):
    def parse_output(self, output):
        return json.loads(output)
        raise Exception("Unable to parse ansible return value: " + output)

    def generate_playbook(self, resource):
        playbook = {"hosts": resource.host, "user": "root"}
        tasks = []
        tasks.append({
            "name": resource.name,
            resource.module: resource.args
        })

        playbook["tasks"] = tasks
        playbook = [playbook]
        file_content = yaml.dump(playbook, default_flow_style=False)
        return file_content

    def run_ansible_cmd(self, resource, dry_run=False):
        tmpfile = None
        playfile = None
        try:
            # generate host file (use mktemp so ansible can read the file as well)
            _, tmpfile = tempfile.mkstemp()
            with open(tmpfile, "w+") as fd:
                fd.write("%s\n" % resource.host)

            # write playbook
            _, playfile = tempfile.mkstemp()
            with open(playfile, "w+") as fd:
                fd.write(self.generate_playbook(resource))

            # build args
            cmd = ["-i", tmpfile]
            if dry_run:
                cmd.append("-C")

            if resource.host == "localhost":
                cmd.append("-c")
                cmd.append("local")

            cmd.append(playfile)

            LOGGER.debug("Executing ansible with %s", cmd)
            env = os.environ
            env["ANSIBLE_STDOUT_CALLBACK"] = "json"
            out, err, retcode = self._io.run("ansible-playbook", cmd, env=env)

            if retcode > 0:
                raise Exception("Ansible module failed: stdout: (%s), stderr(%s)" % (out, err))
            return retcode, self.parse_output(out)

        finally:
            if tmpfile is None:
                os.remove(tmpfile)
            if tmpfile is None:
                os.remove(playfile)

    def process_result(self, resource, json_data):
        # find the task
        for play in json_data["plays"]:
            for task in play["tasks"]:
                if task["task"]["name"] == resource.name:
                    if resource.host not in task["hosts"]:
                        raise Exception("The task was not executed correctly on %s" % resource.host)
                    
                    changed = task["hosts"][resource.host]["changed"]
                    log_msg = ""
                    if "result" in task["hosts"][resource.host]:
                        log_msg = task["hosts"][resource.host]["result"]

                    if "msg" in task["hosts"][resource.host]:
                        log_msg += task["hosts"][resource.host]["msg"]

                    changes = None
                    if "changes" in task["hosts"][resource.host]:
                        changes = task["hosts"][resource.host]["changes"]

                    return {"changed": changed, "changes": changes, "log_msg": log_msg}

        return {}

    def execute(self, resource, dry_run=False):
        """
            Update the given resource
        """
        results = {"changed": False, "changes": {}, "status": "nop", "log_msg": ""}

        try:
            self.pre(resource)

            if resource.require_failed:
                LOGGER.info("Skipping %s because of failed dependencies" % resource.id)
                results["status"] = "skipped"

            retcode, output = self.run_ansible_cmd(resource, dry_run)
            data = self.process_result(resource, output)
            if retcode == 0:
                results["status"] = "deployed"
            else:
                results["status"] = "failed"

            if "changed" in data:
                results["changed"] = data["changed"]
                if results["changed"]:
                    LOGGER.info("%s was changed" % resource.id)
            
            if "changes" in data:
                results["changes"] = data["changes"]

            if "log_msg" in data:
                results["changes"] = data["changes"]

            self.post(resource)

        except Exception as e:
            LOGGER.exception("An error occurred during deployment of %s" % resource.id)
            results["log_msg"] = repr(e)
            results["status"] = "failed"

        return results

