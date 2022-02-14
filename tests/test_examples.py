"""
    Copyright 2022 Inmanta

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
import os
import re


def compile_example(project, name, substitutions=[], pre=""):
    source = os.path.join(os.path.dirname(__file__), "..", "examples", f"{name}.cf")
    with open(source, "r") as fh:
        inp = fh.read()
        for frm, to in substitutions:
            inp = re.sub(frm, to, inp)
        project.compile(pre + inp)


def test_vm(project):
    compile_example(project, "vm")


def test_vm_fip(project):
    compile_example(project, "vm_with_floating_ip")


def test_tenant(project):
    compile_example(project, "tenant")


def test_find_image_and_flavor(project):
    compile_example(
        project,
        "find_image_and_flavor",
        [(r"redhat::centos7", "cirros")],
        pre='cirros=std::OS(name="cirros", version=0.4)',
    )

    assert "image:" in project.get_stdout()
    assert "flavor: m1.small" in project.get_stdout()
