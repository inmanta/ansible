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

import json
import logging
import os
import tempfile
import traceback

import yaml
from inmanta import const
from inmanta.agent.handler import ResourceHandler, SkipResource, provider
from inmanta.resources import Resource, resource

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
        tasks.append({"name": resource.name, resource.module: resource.args})

        playbook["tasks"] = tasks
        playbook = [playbook]
        file_content = yaml.dump(playbook, default_flow_style=False)
        return file_content

    def run_ansible_cmd(self, ctx, resource, dry_run=False):
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
                raise Exception(
                    "Ansible module failed: stdout: (%s), stderr(%s)" % (out, err)
                )
            return retcode, self.parse_output(out)

        finally:
            if tmpfile is None:
                os.remove(tmpfile)
            if tmpfile is None:
                os.remove(playfile)

    def process_result(self, ctx, resource, json_data):
        # find the task
        for play in json_data["plays"]:
            for task in play["tasks"]:
                if task["task"]["name"] == resource.name:
                    if resource.host not in task["hosts"]:
                        raise Exception(
                            "The task was not executed correctly on %s" % resource.host
                        )

                    if "result" in task["hosts"][resource.host]:
                        ctx.info(
                            "result: %(result)s",
                            result=task["hosts"][resource.host]["result"],
                        )

                    if "msg" in task["hosts"][resource.host]:
                        ctx.info(
                            "msg: %(msg)s", msg=task["hosts"][resource.host]["result"]
                        )

    def execute(self, ctx, resource, dry_run=False):
        """
        Update the given resource
        """

        try:
            self.pre(ctx, resource)

            if resource.require_failed:
                ctx.info(
                    msg="Skipping %(resource_id)s because of failed dependencies",
                    resource_id=resource.id,
                )
                ctx.set_status(const.ResourceState.skipped)
                return

            retcode, output = self.run_ansible_cmd(ctx, resource, dry_run)
            self.process_result(ctx, resource, output)
            if retcode == 0:
                if not dry_run:
                    ctx.set_status(const.ResourceState.deployed)

                else:
                    ctx.set_status(const.ResourceState.dry)
            else:
                ctx.set_status(const.ResourceState.failed)

            self.post(ctx, resource)
        except SkipResource as e:
            ctx.set_status(const.ResourceState.skipped)
            ctx.warning(
                msg="Resource %(resource_id)s was skipped: %(reason)s",
                resource_id=resource.id,
                reason=e.args,
            )

        except Exception as e:
            ctx.set_status(const.ResourceState.failed)
            ctx.exception(
                "An error occurred during deployment of %(resource_id)s (excp: %(exception)s",
                resource_id=resource.id,
                exception=repr(e),
                traceback=traceback.format_exc(),
            )
