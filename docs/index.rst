Ansible module
==============

This module allows to call ansible tasks from a configuration module. This module opens up the support in existing ansible
modules without having to implement custom Inmanta handlers. The purpose of this module is to allow other modules to define
high abstraction entities.

Below is an example to illustrate the usage with an example that installs docker, starts docker and start a container. (This
example can also be replicated by using the docker module and native support):

.. code-block:: inmanta
    :linenos:

    import ansible

    p_docker = ansible::Task(module="yum", name="install docker", host="localhost",
                             args={"name": "docker", "state": "installed"})
    s_docker = ansible::Task(module="systemd", name="start docker", host="localhost",
                             args={"name": "docker", "enabled": "yes", "state": "started"},
                             requires=p_docker)

    ubuntu_sleep = ansible::Task(module="docker_container", name="start container", requires=s_docker, host="localhost",
                                 args={"name": "mycontainer", "state": "present", "image": "ubuntu:16.04", "command": "sleep infinity"})


Currently, all tasks are executed in different playbooks. Once resource grouping lands (inmanta#242) more efficient playbooks
can be generated to exploit the parallism that Ansible offers.
